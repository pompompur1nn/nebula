use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-fee-spike-resilience-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_FEE_SPIKE_RESILIENCE_RUNTIME_PROTOCOL_VERSION: &str =
    PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "shake256-domain-separated-canonical-json";
pub const PQ_AUTH_SCHEME: &str = "ml-dsa-87+slh-dsa-shake-256f-fee-spike-resilience-auth-v1";
pub const PQ_SEALING_SCHEME: &str = "ml-kem-1024+xwing-sealed-fee-shock-position-v1";
pub const CONFIDENTIAL_FEE_SCHEME: &str = "ringct-compatible-sealed-low-fee-spike-ledger-v1";
pub const AUCTION_CLEARING_SCHEME: &str = "uniform-price-private-batch-fee-auction-v1";
pub const COMPRESSION_FALLBACK_SCHEME: &str = "calldata-to-blob-to-recursive-proof-fallback-v1";
pub const BRIDGE_EXIT_SMOOTHING_SCHEME: &str = "monero-bridge-exit-fee-ewma-smoothing-v1";
pub const MULTI_ASSET_NETTING_SCHEME: &str = "confidential-multi-asset-fee-netting-v1";
pub const PRECONFIRMATION_REPRICING_SCHEME: &str = "private-preconfirmation-repricing-receipt-v1";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_STABLE_ASSET_ID: &str = "dusd-devnet";
pub const DEVNET_CREDIT_ASSET_ID: &str = "fee-credit-devnet";
pub const DEVNET_HEIGHT: u64 = 1_744_640;
pub const DEVNET_EPOCH: u64 = 2_449;
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_SHOCK_WINDOW_BLOCKS: u64 = 48;
pub const DEFAULT_ORACLE_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_AUCTION_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_REPRICING_TTL_BLOCKS: u64 = 8;
pub const DEFAULT_EXIT_SMOOTHING_WINDOW_BLOCKS: u64 = 180;
pub const DEFAULT_SPONSOR_REFILL_WINDOW_BLOCKS: u64 = 240;
pub const DEFAULT_MAX_DA_PRICE_JUMP_BPS: u64 = 4_000;
pub const DEFAULT_MAX_MONERO_FEE_JUMP_BPS: u64 = 3_500;
pub const DEFAULT_MAX_PROOF_MARKET_JUMP_BPS: u64 = 5_000;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 9;
pub const DEFAULT_HARD_USER_FEE_CAP_BPS: u64 = 30;
pub const DEFAULT_SPONSOR_RESERVE_BPS: u64 = 1_500;
pub const DEFAULT_SPONSOR_DEPLETION_BPS: u64 = 7_500;
pub const DEFAULT_COMPRESSION_TRIGGER_BPS: u64 = 1_800;
pub const DEFAULT_BRIDGE_EXIT_MAX_STEP_BPS: u64 = 450;
pub const DEFAULT_REPRICING_GRACE_BPS: u64 = 250;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 4_096;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 4096;
pub const DEFAULT_MAX_EVENTS: usize = 1_048_576;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShockKind {
    DaPrice,
    MoneroFeeOracle,
    ProofMarket,
    SponsorDepletion,
    BatchAuction,
    CalldataCompression,
    MultiAssetNetting,
    UserFeeCap,
    PreconfirmationRepricing,
    BridgeExitSmoothing,
}

impl ShockKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DaPrice => "da_price",
            Self::MoneroFeeOracle => "monero_fee_oracle",
            Self::ProofMarket => "proof_market",
            Self::SponsorDepletion => "sponsor_depletion",
            Self::BatchAuction => "batch_auction",
            Self::CalldataCompression => "calldata_compression",
            Self::MultiAssetNetting => "multi_asset_netting",
            Self::UserFeeCap => "user_fee_cap",
            Self::PreconfirmationRepricing => "preconfirmation_repricing",
            Self::BridgeExitSmoothing => "bridge_exit_smoothing",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShockSeverity {
    Observe,
    Elevated,
    Severe,
    Critical,
    Recovery,
}

impl ShockSeverity {
    pub fn bps_floor(self) -> u64 {
        match self {
            Self::Observe => 0,
            Self::Elevated => 750,
            Self::Severe => 2_000,
            Self::Critical => 5_000,
            Self::Recovery => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShockStatus {
    Proposed,
    Active,
    Mitigating,
    Smoothed,
    Settled,
    Expired,
    Rejected,
}

impl ShockStatus {
    pub fn open(self) -> bool {
        matches!(self, Self::Proposed | Self::Active | Self::Mitigating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeLaneKind {
    PrivateTransfer,
    ConfidentialSwap,
    ContractCall,
    BatchMintBurn,
    AccountAbstraction,
    BridgeExit,
    SponsorRelay,
    ProofAggregation,
    DataAvailability,
    Preconfirmation,
}

impl FeeLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::ConfidentialSwap => "confidential_swap",
            Self::ContractCall => "contract_call",
            Self::BatchMintBurn => "batch_mint_burn",
            Self::AccountAbstraction => "account_abstraction",
            Self::BridgeExit => "bridge_exit",
            Self::SponsorRelay => "sponsor_relay",
            Self::ProofAggregation => "proof_aggregation",
            Self::DataAvailability => "data_availability",
            Self::Preconfirmation => "preconfirmation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    WrappedMonero,
    StableAsset,
    FeeCredit,
    ConfidentialToken,
    SponsorBond,
    RebateCoupon,
}

impl AssetKind {
    pub fn eligible_for_netting(self) -> bool {
        matches!(
            self,
            Self::WrappedMonero
                | Self::StableAsset
                | Self::FeeCredit
                | Self::ConfidentialToken
                | Self::RebateCoupon
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorPoolStatus {
    Proposed,
    Active,
    Conserving,
    Depleted,
    Refilling,
    Frozen,
    Retired,
}

impl SponsorPoolStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Conserving | Self::Refilling)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Open,
    Clearing,
    Cleared,
    PartiallyFilled,
    Failed,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionMode {
    Calldata,
    BlobDa,
    Dictionary,
    RecursiveProof,
    EmergencyDigest,
}

impl CompressionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Calldata => "calldata",
            Self::BlobDa => "blob_da",
            Self::Dictionary => "dictionary",
            Self::RecursiveProof => "recursive_proof",
            Self::EmergencyDigest => "emergency_digest",
        }
    }

    pub fn stronger_than_calldata(self) -> bool {
        !matches!(self, Self::Calldata)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapDecision {
    Accepted,
    Sponsored,
    RepricedWithinCap,
    Deferred,
    RejectedOverCap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepricingStatus {
    Quoted,
    Accepted,
    SponsorAbsorbed,
    UserCapped,
    Expired,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeExitSmoothingStatus {
    Proposed,
    Active,
    Applied,
    Deferred,
    Settled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_auth_scheme: String,
    pub pq_sealing_scheme: String,
    pub confidential_fee_scheme: String,
    pub auction_clearing_scheme: String,
    pub compression_fallback_scheme: String,
    pub bridge_exit_smoothing_scheme: String,
    pub multi_asset_netting_scheme: String,
    pub preconfirmation_repricing_scheme: String,
    pub epoch: u64,
    pub epoch_blocks: u64,
    pub shock_window_blocks: u64,
    pub oracle_ttl_blocks: u64,
    pub auction_ttl_blocks: u64,
    pub repricing_ttl_blocks: u64,
    pub exit_smoothing_window_blocks: u64,
    pub sponsor_refill_window_blocks: u64,
    pub max_da_price_jump_bps: u64,
    pub max_monero_fee_jump_bps: u64,
    pub max_proof_market_jump_bps: u64,
    pub target_user_fee_bps: u64,
    pub hard_user_fee_cap_bps: u64,
    pub sponsor_reserve_bps: u64,
    pub sponsor_depletion_bps: u64,
    pub compression_trigger_bps: u64,
    pub bridge_exit_max_step_bps: u64,
    pub repricing_grace_bps: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_batch_items: usize,
    pub max_events: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_scheme: PQ_AUTH_SCHEME.to_string(),
            pq_sealing_scheme: PQ_SEALING_SCHEME.to_string(),
            confidential_fee_scheme: CONFIDENTIAL_FEE_SCHEME.to_string(),
            auction_clearing_scheme: AUCTION_CLEARING_SCHEME.to_string(),
            compression_fallback_scheme: COMPRESSION_FALLBACK_SCHEME.to_string(),
            bridge_exit_smoothing_scheme: BRIDGE_EXIT_SMOOTHING_SCHEME.to_string(),
            multi_asset_netting_scheme: MULTI_ASSET_NETTING_SCHEME.to_string(),
            preconfirmation_repricing_scheme: PRECONFIRMATION_REPRICING_SCHEME.to_string(),
            epoch: DEVNET_EPOCH,
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            shock_window_blocks: DEFAULT_SHOCK_WINDOW_BLOCKS,
            oracle_ttl_blocks: DEFAULT_ORACLE_TTL_BLOCKS,
            auction_ttl_blocks: DEFAULT_AUCTION_TTL_BLOCKS,
            repricing_ttl_blocks: DEFAULT_REPRICING_TTL_BLOCKS,
            exit_smoothing_window_blocks: DEFAULT_EXIT_SMOOTHING_WINDOW_BLOCKS,
            sponsor_refill_window_blocks: DEFAULT_SPONSOR_REFILL_WINDOW_BLOCKS,
            max_da_price_jump_bps: DEFAULT_MAX_DA_PRICE_JUMP_BPS,
            max_monero_fee_jump_bps: DEFAULT_MAX_MONERO_FEE_JUMP_BPS,
            max_proof_market_jump_bps: DEFAULT_MAX_PROOF_MARKET_JUMP_BPS,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            hard_user_fee_cap_bps: DEFAULT_HARD_USER_FEE_CAP_BPS,
            sponsor_reserve_bps: DEFAULT_SPONSOR_RESERVE_BPS,
            sponsor_depletion_bps: DEFAULT_SPONSOR_DEPLETION_BPS,
            compression_trigger_bps: DEFAULT_COMPRESSION_TRIGGER_BPS,
            bridge_exit_max_step_bps: DEFAULT_BRIDGE_EXIT_MAX_STEP_BPS,
            repricing_grace_bps: DEFAULT_REPRICING_GRACE_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
            max_events: DEFAULT_MAX_EVENTS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("hash_suite", &self.hash_suite)?;
        require_non_empty("pq_auth_scheme", &self.pq_auth_scheme)?;
        require_non_empty("pq_sealing_scheme", &self.pq_sealing_scheme)?;
        require_non_empty("confidential_fee_scheme", &self.confidential_fee_scheme)?;
        require_non_empty("auction_clearing_scheme", &self.auction_clearing_scheme)?;
        require_non_empty(
            "compression_fallback_scheme",
            &self.compression_fallback_scheme,
        )?;
        require_non_empty(
            "bridge_exit_smoothing_scheme",
            &self.bridge_exit_smoothing_scheme,
        )?;
        require_non_empty(
            "multi_asset_netting_scheme",
            &self.multi_asset_netting_scheme,
        )?;
        require_non_empty(
            "preconfirmation_repricing_scheme",
            &self.preconfirmation_repricing_scheme,
        )?;
        require(self.chain_id == CHAIN_ID, "config chain id mismatch")?;
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "config protocol version mismatch",
        )?;
        require(
            self.schema_version == SCHEMA_VERSION,
            "config schema version mismatch",
        )?;
        require(
            self.epoch_blocks > 0
                && self.shock_window_blocks > 0
                && self.oracle_ttl_blocks > 0
                && self.auction_ttl_blocks > 0
                && self.repricing_ttl_blocks > 0
                && self.exit_smoothing_window_blocks > 0
                && self.sponsor_refill_window_blocks > 0,
            "config block windows must be nonzero",
        )?;
        require(
            self.max_da_price_jump_bps <= MAX_BPS
                && self.max_monero_fee_jump_bps <= MAX_BPS
                && self.max_proof_market_jump_bps <= MAX_BPS
                && self.target_user_fee_bps <= self.hard_user_fee_cap_bps
                && self.hard_user_fee_cap_bps <= MAX_BPS
                && self.sponsor_reserve_bps <= MAX_BPS
                && self.sponsor_depletion_bps <= MAX_BPS
                && self.compression_trigger_bps <= MAX_BPS
                && self.bridge_exit_max_step_bps <= MAX_BPS
                && self.repricing_grace_bps <= MAX_BPS,
            "config basis points out of range",
        )?;
        require(self.min_privacy_set_size > 0, "privacy set must be nonzero")?;
        require(
            self.min_pq_security_bits >= 128,
            "pq security bits below floor",
        )?;
        require(self.max_batch_items > 0, "max batch items must be nonzero")?;
        require(self.max_events > 0, "max events must be nonzero")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "pq_auth_scheme": self.pq_auth_scheme,
            "pq_sealing_scheme": self.pq_sealing_scheme,
            "confidential_fee_scheme": self.confidential_fee_scheme,
            "auction_clearing_scheme": self.auction_clearing_scheme,
            "compression_fallback_scheme": self.compression_fallback_scheme,
            "bridge_exit_smoothing_scheme": self.bridge_exit_smoothing_scheme,
            "multi_asset_netting_scheme": self.multi_asset_netting_scheme,
            "preconfirmation_repricing_scheme": self.preconfirmation_repricing_scheme,
            "epoch": self.epoch,
            "epoch_blocks": self.epoch_blocks,
            "shock_window_blocks": self.shock_window_blocks,
            "oracle_ttl_blocks": self.oracle_ttl_blocks,
            "auction_ttl_blocks": self.auction_ttl_blocks,
            "repricing_ttl_blocks": self.repricing_ttl_blocks,
            "exit_smoothing_window_blocks": self.exit_smoothing_window_blocks,
            "sponsor_refill_window_blocks": self.sponsor_refill_window_blocks,
            "max_da_price_jump_bps": self.max_da_price_jump_bps,
            "max_monero_fee_jump_bps": self.max_monero_fee_jump_bps,
            "max_proof_market_jump_bps": self.max_proof_market_jump_bps,
            "target_user_fee_bps": self.target_user_fee_bps,
            "hard_user_fee_cap_bps": self.hard_user_fee_cap_bps,
            "sponsor_reserve_bps": self.sponsor_reserve_bps,
            "sponsor_depletion_bps": self.sponsor_depletion_bps,
            "compression_trigger_bps": self.compression_trigger_bps,
            "bridge_exit_max_step_bps": self.bridge_exit_max_step_bps,
            "repricing_grace_bps": self.repricing_grace_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_batch_items": self.max_batch_items,
            "max_events": self.max_events
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub next_shock: u64,
    pub next_oracle_sample: u64,
    pub next_sponsor_pool: u64,
    pub next_auction_round: u64,
    pub next_compression_fallback: u64,
    pub next_netting_set: u64,
    pub next_cap_enforcement: u64,
    pub next_repricing_receipt: u64,
    pub next_bridge_exit_smoothing: u64,
    pub next_public_event: u64,
}

impl Counters {
    pub fn devnet() -> Self {
        Self {
            next_shock: 1,
            next_oracle_sample: 1,
            next_sponsor_pool: 1,
            next_auction_round: 1,
            next_compression_fallback: 1,
            next_netting_set: 1,
            next_cap_enforcement: 1,
            next_repricing_receipt: 1,
            next_bridge_exit_smoothing: 1,
            next_public_event: 1,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "next_shock": self.next_shock,
            "next_oracle_sample": self.next_oracle_sample,
            "next_sponsor_pool": self.next_sponsor_pool,
            "next_auction_round": self.next_auction_round,
            "next_compression_fallback": self.next_compression_fallback,
            "next_netting_set": self.next_netting_set,
            "next_cap_enforcement": self.next_cap_enforcement,
            "next_repricing_receipt": self.next_repricing_receipt,
            "next_bridge_exit_smoothing": self.next_bridge_exit_smoothing,
            "next_public_event": self.next_public_event
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub shock_root: String,
    pub oracle_sample_root: String,
    pub sponsor_pool_root: String,
    pub auction_round_root: String,
    pub compression_fallback_root: String,
    pub netting_set_root: String,
    pub cap_enforcement_root: String,
    pub repricing_receipt_root: String,
    pub bridge_exit_smoothing_root: String,
    pub watched_nullifier_root: String,
    pub public_event_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "shock_root": self.shock_root,
            "oracle_sample_root": self.oracle_sample_root,
            "sponsor_pool_root": self.sponsor_pool_root,
            "auction_round_root": self.auction_round_root,
            "compression_fallback_root": self.compression_fallback_root,
            "netting_set_root": self.netting_set_root,
            "cap_enforcement_root": self.cap_enforcement_root,
            "repricing_receipt_root": self.repricing_receipt_root,
            "bridge_exit_smoothing_root": self.bridge_exit_smoothing_root,
            "watched_nullifier_root": self.watched_nullifier_root,
            "public_event_root": self.public_event_root,
            "state_root": self.state_root
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeOracleSample {
    pub sample_id: String,
    pub sequence: u64,
    pub source_committee_id: String,
    pub observed_at_height: u64,
    pub valid_until_height: u64,
    pub da_price_micro_units: u64,
    pub monero_fee_piconero_per_kb: u64,
    pub proof_market_micro_units: u64,
    pub l2_base_fee_micro_units: u64,
    pub confidence_bps: u64,
    pub attestation_root: String,
}

impl FeeOracleSample {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("sample_id", &self.sample_id)?;
        require_non_empty("source_committee_id", &self.source_committee_id)?;
        require_non_empty("attestation_root", &self.attestation_root)?;
        require(
            self.valid_until_height >= self.observed_at_height,
            "oracle sample expires before observation",
        )?;
        require(self.confidence_bps <= MAX_BPS, "oracle confidence too high")?;
        require(
            self.da_price_micro_units > 0
                && self.monero_fee_piconero_per_kb > 0
                && self.proof_market_micro_units > 0
                && self.l2_base_fee_micro_units > 0,
            "oracle prices must be nonzero",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sample_id": self.sample_id,
            "sequence": self.sequence,
            "source_committee_id": self.source_committee_id,
            "observed_at_height": self.observed_at_height,
            "valid_until_height": self.valid_until_height,
            "da_price_micro_units": self.da_price_micro_units,
            "monero_fee_piconero_per_kb": self.monero_fee_piconero_per_kb,
            "proof_market_micro_units": self.proof_market_micro_units,
            "l2_base_fee_micro_units": self.l2_base_fee_micro_units,
            "confidence_bps": self.confidence_bps,
            "attestation_root": self.attestation_root,
            "chain_id": CHAIN_ID
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeShockEvent {
    pub shock_id: String,
    pub sequence: u64,
    pub kind: ShockKind,
    pub severity: ShockSeverity,
    pub status: ShockStatus,
    pub lane: FeeLaneKind,
    pub detected_at_height: u64,
    pub expires_at_height: u64,
    pub baseline_sample_id: String,
    pub observed_sample_id: String,
    pub baseline_price_micro_units: u64,
    pub observed_price_micro_units: u64,
    pub jump_bps: u64,
    pub mitigation_root: String,
    pub note_commitment_root: String,
}

impl FeeShockEvent {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("shock_id", &self.shock_id)?;
        require_non_empty("baseline_sample_id", &self.baseline_sample_id)?;
        require_non_empty("observed_sample_id", &self.observed_sample_id)?;
        require_non_empty("mitigation_root", &self.mitigation_root)?;
        require_non_empty("note_commitment_root", &self.note_commitment_root)?;
        require(
            self.expires_at_height >= self.detected_at_height,
            "shock expires before detection",
        )?;
        require(
            self.baseline_price_micro_units > 0 && self.observed_price_micro_units > 0,
            "shock prices must be nonzero",
        )?;
        require(
            self.jump_bps >= self.severity.bps_floor(),
            "shock jump below severity floor",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "shock_id": self.shock_id,
            "sequence": self.sequence,
            "kind": self.kind,
            "severity": self.severity,
            "status": self.status,
            "lane": self.lane,
            "detected_at_height": self.detected_at_height,
            "expires_at_height": self.expires_at_height,
            "baseline_sample_id": self.baseline_sample_id,
            "observed_sample_id": self.observed_sample_id,
            "baseline_price_micro_units": self.baseline_price_micro_units,
            "observed_price_micro_units": self.observed_price_micro_units,
            "jump_bps": self.jump_bps,
            "mitigation_root": self.mitigation_root,
            "note_commitment_root": self.note_commitment_root,
            "chain_id": CHAIN_ID
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorPoolRecord {
    pub pool_id: String,
    pub sequence: u64,
    pub sponsor_id: String,
    pub status: SponsorPoolStatus,
    pub fee_asset_id: String,
    pub committed_balance_micro_units: u64,
    pub reserved_balance_micro_units: u64,
    pub spent_balance_micro_units: u64,
    pub minimum_reserve_bps: u64,
    pub max_cover_per_batch_micro_units: u64,
    pub replenishment_commitment_root: String,
    pub credential_root: String,
    pub opened_at_height: u64,
    pub refill_due_height: u64,
}

impl SponsorPoolRecord {
    pub fn available_balance(&self) -> u64 {
        self.committed_balance_micro_units
            .saturating_sub(self.reserved_balance_micro_units)
            .saturating_sub(self.spent_balance_micro_units)
    }

    pub fn depletion_bps(&self) -> u64 {
        if self.committed_balance_micro_units == 0 {
            return MAX_BPS;
        }
        self.spent_balance_micro_units
            .saturating_mul(MAX_BPS)
            .saturating_div(self.committed_balance_micro_units)
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("pool_id", &self.pool_id)?;
        require_non_empty("sponsor_id", &self.sponsor_id)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_empty(
            "replenishment_commitment_root",
            &self.replenishment_commitment_root,
        )?;
        require_non_empty("credential_root", &self.credential_root)?;
        require(
            self.minimum_reserve_bps <= MAX_BPS,
            "sponsor reserve bps out of range",
        )?;
        require(
            self.committed_balance_micro_units
                >= self
                    .reserved_balance_micro_units
                    .saturating_add(self.spent_balance_micro_units),
            "sponsor pool over-allocated",
        )?;
        require(
            self.refill_due_height >= self.opened_at_height,
            "sponsor refill due before opened height",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "sequence": self.sequence,
            "sponsor_id": self.sponsor_id,
            "status": self.status,
            "fee_asset_id": self.fee_asset_id,
            "committed_balance_micro_units": self.committed_balance_micro_units,
            "reserved_balance_micro_units": self.reserved_balance_micro_units,
            "spent_balance_micro_units": self.spent_balance_micro_units,
            "available_balance_micro_units": self.available_balance(),
            "depletion_bps": self.depletion_bps(),
            "minimum_reserve_bps": self.minimum_reserve_bps,
            "max_cover_per_batch_micro_units": self.max_cover_per_batch_micro_units,
            "replenishment_commitment_root": self.replenishment_commitment_root,
            "credential_root": self.credential_root,
            "opened_at_height": self.opened_at_height,
            "refill_due_height": self.refill_due_height,
            "chain_id": CHAIN_ID
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuctionBidCommitment {
    pub bid_id: String,
    pub bidder_id: String,
    pub lane: FeeLaneKind,
    pub max_fee_micro_units: u64,
    pub quantity_units: u64,
    pub fee_cap_bps: u64,
    pub sponsor_pool_id: Option<String>,
    pub sealed_bid_root: String,
}

impl AuctionBidCommitment {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("bid_id", &self.bid_id)?;
        require_non_empty("bidder_id", &self.bidder_id)?;
        require_non_empty("sealed_bid_root", &self.sealed_bid_root)?;
        require(self.max_fee_micro_units > 0, "bid max fee must be nonzero")?;
        require(self.quantity_units > 0, "bid quantity must be nonzero")?;
        require(self.fee_cap_bps <= MAX_BPS, "bid fee cap out of range")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "bidder_id": self.bidder_id,
            "lane": self.lane,
            "max_fee_micro_units": self.max_fee_micro_units,
            "quantity_units": self.quantity_units,
            "fee_cap_bps": self.fee_cap_bps,
            "sponsor_pool_id": self.sponsor_pool_id,
            "sealed_bid_root": self.sealed_bid_root,
            "chain_id": CHAIN_ID
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuctionRound {
    pub auction_id: String,
    pub sequence: u64,
    pub status: AuctionStatus,
    pub lane: FeeLaneKind,
    pub shock_id: Option<String>,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub target_quantity_units: u64,
    pub clearing_price_micro_units: u64,
    pub filled_quantity_units: u64,
    pub uniform_discount_bps: u64,
    pub bid_ids: BTreeSet<String>,
    pub winning_bid_ids: BTreeSet<String>,
    pub clearing_proof_root: String,
}

impl AuctionRound {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("auction_id", &self.auction_id)?;
        require_non_empty("clearing_proof_root", &self.clearing_proof_root)?;
        require(
            self.closes_at_height >= self.opened_at_height,
            "auction closes before opening",
        )?;
        require(
            self.target_quantity_units > 0,
            "auction target quantity must be nonzero",
        )?;
        require(
            self.filled_quantity_units <= self.target_quantity_units,
            "auction filled quantity exceeds target",
        )?;
        require(
            self.uniform_discount_bps <= MAX_BPS,
            "auction discount bps out of range",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "sequence": self.sequence,
            "status": self.status,
            "lane": self.lane,
            "shock_id": self.shock_id,
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
            "target_quantity_units": self.target_quantity_units,
            "clearing_price_micro_units": self.clearing_price_micro_units,
            "filled_quantity_units": self.filled_quantity_units,
            "uniform_discount_bps": self.uniform_discount_bps,
            "bid_ids": self.bid_ids,
            "winning_bid_ids": self.winning_bid_ids,
            "clearing_proof_root": self.clearing_proof_root,
            "chain_id": CHAIN_ID
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionFallbackRecord {
    pub fallback_id: String,
    pub sequence: u64,
    pub shock_id: Option<String>,
    pub lane: FeeLaneKind,
    pub previous_mode: CompressionMode,
    pub selected_mode: CompressionMode,
    pub raw_bytes: u64,
    pub compressed_bytes: u64,
    pub compression_ratio_bps: u64,
    pub da_savings_micro_units: u64,
    pub dictionary_root: String,
    pub proof_root: String,
    pub activated_at_height: u64,
}

impl CompressionFallbackRecord {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("fallback_id", &self.fallback_id)?;
        require_non_empty("dictionary_root", &self.dictionary_root)?;
        require_non_empty("proof_root", &self.proof_root)?;
        require(self.raw_bytes > 0, "compression raw bytes must be nonzero")?;
        require(
            self.compressed_bytes <= self.raw_bytes,
            "compressed bytes exceed raw bytes",
        )?;
        require(
            self.compression_ratio_bps <= MAX_BPS,
            "compression ratio out of range",
        )?;
        require(
            self.selected_mode.stronger_than_calldata(),
            "fallback selected calldata mode",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fallback_id": self.fallback_id,
            "sequence": self.sequence,
            "shock_id": self.shock_id,
            "lane": self.lane,
            "previous_mode": self.previous_mode,
            "selected_mode": self.selected_mode,
            "raw_bytes": self.raw_bytes,
            "compressed_bytes": self.compressed_bytes,
            "compression_ratio_bps": self.compression_ratio_bps,
            "da_savings_micro_units": self.da_savings_micro_units,
            "dictionary_root": self.dictionary_root,
            "proof_root": self.proof_root,
            "activated_at_height": self.activated_at_height,
            "chain_id": CHAIN_ID
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NettingAssetLine {
    pub asset_id: String,
    pub asset_kind: AssetKind,
    pub debit_micro_units: u64,
    pub credit_micro_units: u64,
    pub oracle_rate_micro_units: u64,
    pub settlement_priority: u16,
}

impl NettingAssetLine {
    pub fn net_credit(&self) -> u64 {
        self.credit_micro_units
            .saturating_sub(self.debit_micro_units)
    }

    pub fn net_debit(&self) -> u64 {
        self.debit_micro_units
            .saturating_sub(self.credit_micro_units)
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("asset_id", &self.asset_id)?;
        require(
            self.asset_kind.eligible_for_netting(),
            "asset kind not eligible for netting",
        )?;
        require(
            self.debit_micro_units > 0 || self.credit_micro_units > 0,
            "netting line must carry value",
        )?;
        require(
            self.oracle_rate_micro_units > 0,
            "netting oracle rate must be nonzero",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "asset_id": self.asset_id,
            "asset_kind": self.asset_kind,
            "debit_micro_units": self.debit_micro_units,
            "credit_micro_units": self.credit_micro_units,
            "net_credit_micro_units": self.net_credit(),
            "net_debit_micro_units": self.net_debit(),
            "oracle_rate_micro_units": self.oracle_rate_micro_units,
            "settlement_priority": self.settlement_priority,
            "chain_id": CHAIN_ID
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiAssetNettingSet {
    pub netting_id: String,
    pub sequence: u64,
    pub lane: FeeLaneKind,
    pub auction_id: Option<String>,
    pub sponsor_pool_id: Option<String>,
    pub participant_count: u64,
    pub privacy_set_size: u64,
    pub lines: Vec<NettingAssetLine>,
    pub residual_fee_micro_units: u64,
    pub settlement_root: String,
    pub created_at_height: u64,
}

impl MultiAssetNettingSet {
    pub fn total_debit(&self) -> u64 {
        self.lines
            .iter()
            .map(|line| line.debit_micro_units)
            .fold(0_u64, u64::saturating_add)
    }

    pub fn total_credit(&self) -> u64 {
        self.lines
            .iter()
            .map(|line| line.credit_micro_units)
            .fold(0_u64, u64::saturating_add)
    }

    pub fn validate(&self, min_privacy_set_size: u64) -> Result<()> {
        require_non_empty("netting_id", &self.netting_id)?;
        require_non_empty("settlement_root", &self.settlement_root)?;
        require(!self.lines.is_empty(), "netting set has no lines")?;
        require(
            self.privacy_set_size >= min_privacy_set_size,
            "netting privacy set below floor",
        )?;
        require(
            self.participant_count > 0 && self.participant_count <= self.privacy_set_size,
            "netting participant count invalid",
        )?;
        for line in &self.lines {
            line.validate()?;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        let lines: Vec<Value> = self
            .lines
            .iter()
            .map(NettingAssetLine::public_record)
            .collect();
        json!({
            "netting_id": self.netting_id,
            "sequence": self.sequence,
            "lane": self.lane,
            "auction_id": self.auction_id,
            "sponsor_pool_id": self.sponsor_pool_id,
            "participant_count": self.participant_count,
            "privacy_set_size": self.privacy_set_size,
            "total_debit_micro_units": self.total_debit(),
            "total_credit_micro_units": self.total_credit(),
            "residual_fee_micro_units": self.residual_fee_micro_units,
            "lines": lines,
            "settlement_root": self.settlement_root,
            "created_at_height": self.created_at_height,
            "chain_id": CHAIN_ID
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapEnforcementRecord {
    pub cap_id: String,
    pub sequence: u64,
    pub account_commitment: String,
    pub lane: FeeLaneKind,
    pub requested_fee_micro_units: u64,
    pub capped_fee_micro_units: u64,
    pub cap_bps: u64,
    pub sponsor_pool_id: Option<String>,
    pub decision: CapDecision,
    pub policy_root: String,
    pub enforced_at_height: u64,
}

impl CapEnforcementRecord {
    pub fn sponsor_delta(&self) -> u64 {
        self.requested_fee_micro_units
            .saturating_sub(self.capped_fee_micro_units)
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("cap_id", &self.cap_id)?;
        require_non_empty("account_commitment", &self.account_commitment)?;
        require_non_empty("policy_root", &self.policy_root)?;
        require(
            self.requested_fee_micro_units > 0,
            "cap requested fee must be nonzero",
        )?;
        require(
            self.capped_fee_micro_units <= self.requested_fee_micro_units,
            "capped fee exceeds requested fee",
        )?;
        require(self.cap_bps <= MAX_BPS, "cap bps out of range")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "cap_id": self.cap_id,
            "sequence": self.sequence,
            "account_commitment": self.account_commitment,
            "lane": self.lane,
            "requested_fee_micro_units": self.requested_fee_micro_units,
            "capped_fee_micro_units": self.capped_fee_micro_units,
            "sponsor_delta_micro_units": self.sponsor_delta(),
            "cap_bps": self.cap_bps,
            "sponsor_pool_id": self.sponsor_pool_id,
            "decision": self.decision,
            "policy_root": self.policy_root,
            "enforced_at_height": self.enforced_at_height,
            "chain_id": CHAIN_ID
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepricingReceipt {
    pub receipt_id: String,
    pub sequence: u64,
    pub preconfirmation_id: String,
    pub account_commitment: String,
    pub shock_id: Option<String>,
    pub status: RepricingStatus,
    pub original_fee_micro_units: u64,
    pub repriced_fee_micro_units: u64,
    pub user_cap_micro_units: u64,
    pub sponsor_absorbed_micro_units: u64,
    pub valid_until_height: u64,
    pub issued_at_height: u64,
    pub receipt_root: String,
}

impl RepricingReceipt {
    pub fn user_delta(&self) -> u64 {
        self.repriced_fee_micro_units
            .saturating_sub(self.original_fee_micro_units)
            .saturating_sub(self.sponsor_absorbed_micro_units)
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("receipt_id", &self.receipt_id)?;
        require_non_empty("preconfirmation_id", &self.preconfirmation_id)?;
        require_non_empty("account_commitment", &self.account_commitment)?;
        require_non_empty("receipt_root", &self.receipt_root)?;
        require(
            self.original_fee_micro_units > 0 && self.repriced_fee_micro_units > 0,
            "repricing fees must be nonzero",
        )?;
        require(
            self.valid_until_height >= self.issued_at_height,
            "repricing receipt expires before issue",
        )?;
        require(
            self.user_delta() <= self.user_cap_micro_units,
            "repricing user delta exceeds cap",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "sequence": self.sequence,
            "preconfirmation_id": self.preconfirmation_id,
            "account_commitment": self.account_commitment,
            "shock_id": self.shock_id,
            "status": self.status,
            "original_fee_micro_units": self.original_fee_micro_units,
            "repriced_fee_micro_units": self.repriced_fee_micro_units,
            "user_cap_micro_units": self.user_cap_micro_units,
            "sponsor_absorbed_micro_units": self.sponsor_absorbed_micro_units,
            "user_delta_micro_units": self.user_delta(),
            "valid_until_height": self.valid_until_height,
            "issued_at_height": self.issued_at_height,
            "receipt_root": self.receipt_root,
            "chain_id": CHAIN_ID
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeExitFeeSmoothingRecord {
    pub smoothing_id: String,
    pub sequence: u64,
    pub exit_batch_id: String,
    pub status: BridgeExitSmoothingStatus,
    pub monero_height: u64,
    pub l2_height: u64,
    pub raw_exit_fee_piconero: u64,
    pub smoothed_exit_fee_piconero: u64,
    pub previous_smoothed_fee_piconero: u64,
    pub max_step_bps: u64,
    pub smoothing_window_blocks: u64,
    pub liquidity_provider_root: String,
    pub exit_manifest_root: String,
}

impl BridgeExitFeeSmoothingRecord {
    pub fn step_bps(&self) -> u64 {
        if self.previous_smoothed_fee_piconero == 0 {
            return MAX_BPS;
        }
        self.smoothed_exit_fee_piconero
            .abs_diff(self.previous_smoothed_fee_piconero)
            .saturating_mul(MAX_BPS)
            .saturating_div(self.previous_smoothed_fee_piconero)
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("smoothing_id", &self.smoothing_id)?;
        require_non_empty("exit_batch_id", &self.exit_batch_id)?;
        require_non_empty("liquidity_provider_root", &self.liquidity_provider_root)?;
        require_non_empty("exit_manifest_root", &self.exit_manifest_root)?;
        require(
            self.raw_exit_fee_piconero > 0 && self.smoothed_exit_fee_piconero > 0,
            "bridge exit fees must be nonzero",
        )?;
        require(self.max_step_bps <= MAX_BPS, "max step bps out of range")?;
        require(
            self.smoothing_window_blocks > 0,
            "smoothing window must be nonzero",
        )?;
        if self.previous_smoothed_fee_piconero > 0 {
            require(
                self.step_bps() <= self.max_step_bps,
                "smoothed bridge exit fee exceeds max step",
            )?;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "smoothing_id": self.smoothing_id,
            "sequence": self.sequence,
            "exit_batch_id": self.exit_batch_id,
            "status": self.status,
            "monero_height": self.monero_height,
            "l2_height": self.l2_height,
            "raw_exit_fee_piconero": self.raw_exit_fee_piconero,
            "smoothed_exit_fee_piconero": self.smoothed_exit_fee_piconero,
            "previous_smoothed_fee_piconero": self.previous_smoothed_fee_piconero,
            "step_bps": self.step_bps(),
            "max_step_bps": self.max_step_bps,
            "smoothing_window_blocks": self.smoothing_window_blocks,
            "liquidity_provider_root": self.liquidity_provider_root,
            "exit_manifest_root": self.exit_manifest_root,
            "chain_id": CHAIN_ID
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicEvent {
    pub event_id: String,
    pub sequence: u64,
    pub kind: ShockKind,
    pub subject_id: String,
    pub height: u64,
    pub severity: ShockSeverity,
    pub record_root: String,
    pub metadata: BTreeMap<String, String>,
}

impl PublicEvent {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("event_id", &self.event_id)?;
        require_non_empty("subject_id", &self.subject_id)?;
        require_non_empty("record_root", &self.record_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "sequence": self.sequence,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "height": self.height,
            "severity": self.severity,
            "record_root": self.record_root,
            "metadata": self.metadata,
            "chain_id": CHAIN_ID
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub oracle_samples: BTreeMap<String, FeeOracleSample>,
    pub shocks: BTreeMap<String, FeeShockEvent>,
    pub sponsor_pools: BTreeMap<String, SponsorPoolRecord>,
    pub auction_bids: BTreeMap<String, AuctionBidCommitment>,
    pub auction_rounds: BTreeMap<String, AuctionRound>,
    pub compression_fallbacks: BTreeMap<String, CompressionFallbackRecord>,
    pub netting_sets: BTreeMap<String, MultiAssetNettingSet>,
    pub cap_enforcements: BTreeMap<String, CapEnforcementRecord>,
    pub repricing_receipts: BTreeMap<String, RepricingReceipt>,
    pub bridge_exit_smoothing: BTreeMap<String, BridgeExitFeeSmoothingRecord>,
    pub watched_nullifiers: BTreeSet<String>,
    pub public_events: BTreeMap<String, PublicEvent>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::devnet(),
            oracle_samples: BTreeMap::new(),
            shocks: BTreeMap::new(),
            sponsor_pools: BTreeMap::new(),
            auction_bids: BTreeMap::new(),
            auction_rounds: BTreeMap::new(),
            compression_fallbacks: BTreeMap::new(),
            netting_sets: BTreeMap::new(),
            cap_enforcements: BTreeMap::new(),
            repricing_receipts: BTreeMap::new(),
            bridge_exit_smoothing: BTreeMap::new(),
            watched_nullifiers: BTreeSet::new(),
            public_events: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::devnet(),
            oracle_samples: BTreeMap::new(),
            shocks: BTreeMap::new(),
            sponsor_pools: BTreeMap::new(),
            auction_bids: BTreeMap::new(),
            auction_rounds: BTreeMap::new(),
            compression_fallbacks: BTreeMap::new(),
            netting_sets: BTreeMap::new(),
            cap_enforcements: BTreeMap::new(),
            repricing_receipts: BTreeMap::new(),
            bridge_exit_smoothing: BTreeMap::new(),
            watched_nullifiers: BTreeSet::new(),
            public_events: BTreeMap::new(),
        };
        state.seed_devnet();
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        for sample in self.oracle_samples.values() {
            sample.validate()?;
        }
        for shock in self.shocks.values() {
            shock.validate()?;
            require(
                self.oracle_samples.contains_key(&shock.baseline_sample_id),
                "shock baseline sample missing",
            )?;
            require(
                self.oracle_samples.contains_key(&shock.observed_sample_id),
                "shock observed sample missing",
            )?;
        }
        for pool in self.sponsor_pools.values() {
            pool.validate()?;
        }
        for bid in self.auction_bids.values() {
            bid.validate()?;
            if let Some(pool_id) = &bid.sponsor_pool_id {
                require(
                    self.sponsor_pools.contains_key(pool_id),
                    "bid sponsor pool missing",
                )?;
            }
        }
        for round in self.auction_rounds.values() {
            round.validate()?;
            if let Some(shock_id) = &round.shock_id {
                require(self.shocks.contains_key(shock_id), "auction shock missing")?;
            }
            for bid_id in &round.bid_ids {
                require(
                    self.auction_bids.contains_key(bid_id),
                    "auction bid missing",
                )?;
            }
            for bid_id in &round.winning_bid_ids {
                require(
                    round.bid_ids.contains(bid_id),
                    "auction winning bid not in bid set",
                )?;
            }
        }
        for fallback in self.compression_fallbacks.values() {
            fallback.validate()?;
            if let Some(shock_id) = &fallback.shock_id {
                require(self.shocks.contains_key(shock_id), "fallback shock missing")?;
            }
        }
        for netting in self.netting_sets.values() {
            netting.validate(self.config.min_privacy_set_size)?;
            if let Some(pool_id) = &netting.sponsor_pool_id {
                require(
                    self.sponsor_pools.contains_key(pool_id),
                    "netting sponsor pool missing",
                )?;
            }
            if let Some(auction_id) = &netting.auction_id {
                require(
                    self.auction_rounds.contains_key(auction_id),
                    "netting auction missing",
                )?;
            }
        }
        for cap in self.cap_enforcements.values() {
            cap.validate()?;
            if let Some(pool_id) = &cap.sponsor_pool_id {
                require(
                    self.sponsor_pools.contains_key(pool_id),
                    "cap sponsor pool missing",
                )?;
            }
        }
        for receipt in self.repricing_receipts.values() {
            receipt.validate()?;
            if let Some(shock_id) = &receipt.shock_id {
                require(self.shocks.contains_key(shock_id), "receipt shock missing")?;
            }
        }
        for smoothing in self.bridge_exit_smoothing.values() {
            smoothing.validate()?;
        }
        for nullifier in &self.watched_nullifiers {
            require_non_empty("watched_nullifier", nullifier)?;
        }
        for event in self.public_events.values() {
            event.validate()?;
        }
        Ok(())
    }

    pub fn record_oracle_sample(
        &mut self,
        source_committee_id: impl Into<String>,
        observed_at_height: u64,
        da_price_micro_units: u64,
        monero_fee_piconero_per_kb: u64,
        proof_market_micro_units: u64,
        l2_base_fee_micro_units: u64,
        confidence_bps: u64,
        attestation_root: impl Into<String>,
    ) -> Result<String> {
        let sequence = self.counters.next_oracle_sample;
        let source_committee_id = source_committee_id.into();
        let attestation_root = attestation_root.into();
        let valid_until_height = observed_at_height.saturating_add(self.config.oracle_ttl_blocks);
        let sample_id = oracle_sample_id(sequence, &source_committee_id, observed_at_height);
        let sample = FeeOracleSample {
            sample_id: sample_id.clone(),
            sequence,
            source_committee_id,
            observed_at_height,
            valid_until_height,
            da_price_micro_units,
            monero_fee_piconero_per_kb,
            proof_market_micro_units,
            l2_base_fee_micro_units,
            confidence_bps,
            attestation_root,
        };
        sample.validate()?;
        self.counters.next_oracle_sample = self.counters.next_oracle_sample.saturating_add(1);
        self.oracle_samples.insert(sample_id.clone(), sample);
        Ok(sample_id)
    }

    pub fn register_shock(
        &mut self,
        kind: ShockKind,
        lane: FeeLaneKind,
        baseline_sample_id: impl Into<String>,
        observed_sample_id: impl Into<String>,
        detected_at_height: u64,
        mitigation_root: impl Into<String>,
        note_commitment_root: impl Into<String>,
    ) -> Result<String> {
        let baseline_sample_id = baseline_sample_id.into();
        let observed_sample_id = observed_sample_id.into();
        let baseline = self
            .oracle_samples
            .get(&baseline_sample_id)
            .ok_or_else(|| "baseline oracle sample missing".to_string())?;
        let observed = self
            .oracle_samples
            .get(&observed_sample_id)
            .ok_or_else(|| "observed oracle sample missing".to_string())?;
        let baseline_price = sample_price_for_kind(baseline, kind);
        let observed_price = sample_price_for_kind(observed, kind);
        let jump_bps = bps_delta(baseline_price, observed_price);
        let severity = severity_for_jump(jump_bps);
        let sequence = self.counters.next_shock;
        let shock_id = shock_id(sequence, kind, lane, detected_at_height);
        let shock = FeeShockEvent {
            shock_id: shock_id.clone(),
            sequence,
            kind,
            severity,
            status: ShockStatus::Active,
            lane,
            detected_at_height,
            expires_at_height: detected_at_height.saturating_add(self.config.shock_window_blocks),
            baseline_sample_id,
            observed_sample_id,
            baseline_price_micro_units: baseline_price,
            observed_price_micro_units: observed_price,
            jump_bps,
            mitigation_root: mitigation_root.into(),
            note_commitment_root: note_commitment_root.into(),
        };
        shock.validate()?;
        self.counters.next_shock = self.counters.next_shock.saturating_add(1);
        self.shocks.insert(shock_id.clone(), shock);
        self.emit_event(kind, shock_id.clone(), detected_at_height, severity)?;
        Ok(shock_id)
    }

    pub fn register_sponsor_pool(
        &mut self,
        sponsor_id: impl Into<String>,
        fee_asset_id: impl Into<String>,
        committed_balance_micro_units: u64,
        max_cover_per_batch_micro_units: u64,
        opened_at_height: u64,
        replenishment_commitment_root: impl Into<String>,
        credential_root: impl Into<String>,
    ) -> Result<String> {
        let sequence = self.counters.next_sponsor_pool;
        let sponsor_id = sponsor_id.into();
        let fee_asset_id = fee_asset_id.into();
        let pool_id = sponsor_pool_id(sequence, &sponsor_id, &fee_asset_id);
        let reserve = committed_balance_micro_units
            .saturating_mul(self.config.sponsor_reserve_bps)
            .saturating_div(MAX_BPS);
        let pool = SponsorPoolRecord {
            pool_id: pool_id.clone(),
            sequence,
            sponsor_id,
            status: SponsorPoolStatus::Active,
            fee_asset_id,
            committed_balance_micro_units,
            reserved_balance_micro_units: reserve,
            spent_balance_micro_units: 0,
            minimum_reserve_bps: self.config.sponsor_reserve_bps,
            max_cover_per_batch_micro_units,
            replenishment_commitment_root: replenishment_commitment_root.into(),
            credential_root: credential_root.into(),
            opened_at_height,
            refill_due_height: opened_at_height
                .saturating_add(self.config.sponsor_refill_window_blocks),
        };
        pool.validate()?;
        self.counters.next_sponsor_pool = self.counters.next_sponsor_pool.saturating_add(1);
        self.sponsor_pools.insert(pool_id.clone(), pool);
        Ok(pool_id)
    }

    pub fn submit_auction_bid(
        &mut self,
        bidder_id: impl Into<String>,
        lane: FeeLaneKind,
        max_fee_micro_units: u64,
        quantity_units: u64,
        fee_cap_bps: u64,
        sponsor_pool_id: Option<String>,
        sealed_bid_root: impl Into<String>,
    ) -> Result<String> {
        if let Some(pool_id) = &sponsor_pool_id {
            require(
                self.sponsor_pools.contains_key(pool_id),
                "bid sponsor pool missing",
            )?;
        }
        let bidder_id = bidder_id.into();
        let bid_id = bid_id(
            self.auction_bids.len() as u64 + 1,
            &bidder_id,
            lane,
            max_fee_micro_units,
        );
        let bid = AuctionBidCommitment {
            bid_id: bid_id.clone(),
            bidder_id,
            lane,
            max_fee_micro_units,
            quantity_units,
            fee_cap_bps,
            sponsor_pool_id,
            sealed_bid_root: sealed_bid_root.into(),
        };
        bid.validate()?;
        self.auction_bids.insert(bid_id.clone(), bid);
        Ok(bid_id)
    }

    pub fn open_auction_round(
        &mut self,
        lane: FeeLaneKind,
        shock_id: Option<String>,
        opened_at_height: u64,
        target_quantity_units: u64,
        bid_ids: BTreeSet<String>,
        clearing_proof_root: impl Into<String>,
    ) -> Result<String> {
        if let Some(id) = &shock_id {
            require(self.shocks.contains_key(id), "auction shock missing")?;
        }
        for bid_id in &bid_ids {
            require(
                self.auction_bids.contains_key(bid_id),
                "auction bid missing",
            )?;
        }
        let sequence = self.counters.next_auction_round;
        let auction_id = auction_round_id(sequence, lane, opened_at_height);
        let round = AuctionRound {
            auction_id: auction_id.clone(),
            sequence,
            status: AuctionStatus::Open,
            lane,
            shock_id,
            opened_at_height,
            closes_at_height: opened_at_height.saturating_add(self.config.auction_ttl_blocks),
            target_quantity_units,
            clearing_price_micro_units: 0,
            filled_quantity_units: 0,
            uniform_discount_bps: 0,
            bid_ids,
            winning_bid_ids: BTreeSet::new(),
            clearing_proof_root: clearing_proof_root.into(),
        };
        round.validate()?;
        self.counters.next_auction_round = self.counters.next_auction_round.saturating_add(1);
        self.auction_rounds.insert(auction_id.clone(), round);
        Ok(auction_id)
    }

    pub fn clear_auction_round(
        &mut self,
        auction_id: &str,
        clearing_price_micro_units: u64,
        uniform_discount_bps: u64,
    ) -> Result<()> {
        let round = self
            .auction_rounds
            .get_mut(auction_id)
            .ok_or_else(|| "auction round missing".to_string())?;
        require(
            matches!(round.status, AuctionStatus::Open | AuctionStatus::Clearing),
            "auction not open for clearing",
        )?;
        let mut winners = BTreeSet::new();
        let mut filled = 0_u64;
        for bid_id in &round.bid_ids {
            if let Some(bid) = self.auction_bids.get(bid_id) {
                if bid.max_fee_micro_units >= clearing_price_micro_units
                    && bid.fee_cap_bps <= self.config.hard_user_fee_cap_bps
                {
                    winners.insert(bid_id.clone());
                    filled = filled.saturating_add(bid.quantity_units);
                    if filled >= round.target_quantity_units {
                        break;
                    }
                }
            }
        }
        round.clearing_price_micro_units = clearing_price_micro_units;
        round.uniform_discount_bps = uniform_discount_bps;
        round.filled_quantity_units = filled.min(round.target_quantity_units);
        round.winning_bid_ids = winners;
        round.status = if round.filled_quantity_units == round.target_quantity_units {
            AuctionStatus::Cleared
        } else if round.filled_quantity_units > 0 {
            AuctionStatus::PartiallyFilled
        } else {
            AuctionStatus::Failed
        };
        round.validate()
    }

    pub fn activate_compression_fallback(
        &mut self,
        shock_id: Option<String>,
        lane: FeeLaneKind,
        previous_mode: CompressionMode,
        selected_mode: CompressionMode,
        raw_bytes: u64,
        compressed_bytes: u64,
        activated_at_height: u64,
        dictionary_root: impl Into<String>,
        proof_root: impl Into<String>,
    ) -> Result<String> {
        if let Some(id) = &shock_id {
            require(self.shocks.contains_key(id), "fallback shock missing")?;
        }
        let sequence = self.counters.next_compression_fallback;
        let fallback_id = compression_fallback_id(sequence, lane, activated_at_height);
        let ratio = compressed_bytes
            .saturating_mul(MAX_BPS)
            .saturating_div(raw_bytes.max(1));
        let fallback = CompressionFallbackRecord {
            fallback_id: fallback_id.clone(),
            sequence,
            shock_id,
            lane,
            previous_mode,
            selected_mode,
            raw_bytes,
            compressed_bytes,
            compression_ratio_bps: ratio,
            da_savings_micro_units: raw_bytes.saturating_sub(compressed_bytes),
            dictionary_root: dictionary_root.into(),
            proof_root: proof_root.into(),
            activated_at_height,
        };
        fallback.validate()?;
        self.counters.next_compression_fallback =
            self.counters.next_compression_fallback.saturating_add(1);
        self.compression_fallbacks
            .insert(fallback_id.clone(), fallback);
        Ok(fallback_id)
    }

    pub fn create_netting_set(
        &mut self,
        lane: FeeLaneKind,
        auction_id: Option<String>,
        sponsor_pool_id: Option<String>,
        participant_count: u64,
        privacy_set_size: u64,
        lines: Vec<NettingAssetLine>,
        residual_fee_micro_units: u64,
        created_at_height: u64,
    ) -> Result<String> {
        if let Some(id) = &auction_id {
            require(
                self.auction_rounds.contains_key(id),
                "netting auction missing",
            )?;
        }
        if let Some(id) = &sponsor_pool_id {
            require(
                self.sponsor_pools.contains_key(id),
                "netting sponsor pool missing",
            )?;
        }
        let sequence = self.counters.next_netting_set;
        let settlement_root = lines_root("FEE-SPIKE-NETTING-LINE", &lines);
        let netting_id = netting_set_id(sequence, lane, &settlement_root);
        let set = MultiAssetNettingSet {
            netting_id: netting_id.clone(),
            sequence,
            lane,
            auction_id,
            sponsor_pool_id,
            participant_count,
            privacy_set_size,
            lines,
            residual_fee_micro_units,
            settlement_root,
            created_at_height,
        };
        set.validate(self.config.min_privacy_set_size)?;
        self.counters.next_netting_set = self.counters.next_netting_set.saturating_add(1);
        self.netting_sets.insert(netting_id.clone(), set);
        Ok(netting_id)
    }

    pub fn enforce_user_fee_cap(
        &mut self,
        account_commitment: impl Into<String>,
        lane: FeeLaneKind,
        requested_fee_micro_units: u64,
        user_cap_micro_units: u64,
        sponsor_pool_id: Option<String>,
        enforced_at_height: u64,
        policy_root: impl Into<String>,
    ) -> Result<String> {
        if let Some(id) = &sponsor_pool_id {
            require(
                self.sponsor_pools.contains_key(id),
                "cap sponsor pool missing",
            )?;
        }
        let capped_fee = requested_fee_micro_units.min(user_cap_micro_units);
        let decision = if requested_fee_micro_units <= user_cap_micro_units {
            CapDecision::Accepted
        } else if sponsor_pool_id.is_some() {
            CapDecision::Sponsored
        } else {
            CapDecision::RejectedOverCap
        };
        let sequence = self.counters.next_cap_enforcement;
        let account_commitment = account_commitment.into();
        let cap_id = cap_enforcement_id(sequence, &account_commitment, lane, enforced_at_height);
        let record = CapEnforcementRecord {
            cap_id: cap_id.clone(),
            sequence,
            account_commitment,
            lane,
            requested_fee_micro_units,
            capped_fee_micro_units: capped_fee,
            cap_bps: self.config.hard_user_fee_cap_bps,
            sponsor_pool_id,
            decision,
            policy_root: policy_root.into(),
            enforced_at_height,
        };
        record.validate()?;
        self.counters.next_cap_enforcement = self.counters.next_cap_enforcement.saturating_add(1);
        self.cap_enforcements.insert(cap_id.clone(), record);
        Ok(cap_id)
    }

    pub fn issue_repricing_receipt(
        &mut self,
        preconfirmation_id: impl Into<String>,
        account_commitment: impl Into<String>,
        shock_id: Option<String>,
        original_fee_micro_units: u64,
        repriced_fee_micro_units: u64,
        user_cap_micro_units: u64,
        issued_at_height: u64,
    ) -> Result<String> {
        if let Some(id) = &shock_id {
            require(self.shocks.contains_key(id), "repricing shock missing")?;
        }
        let sequence = self.counters.next_repricing_receipt;
        let preconfirmation_id = preconfirmation_id.into();
        let account_commitment = account_commitment.into();
        let receipt_id = repricing_receipt_id(sequence, &preconfirmation_id, &account_commitment);
        let sponsor_absorbed = repriced_fee_micro_units
            .saturating_sub(original_fee_micro_units)
            .saturating_sub(user_cap_micro_units);
        let status = if repriced_fee_micro_units <= original_fee_micro_units {
            RepricingStatus::Accepted
        } else if sponsor_absorbed > 0 {
            RepricingStatus::SponsorAbsorbed
        } else {
            RepricingStatus::UserCapped
        };
        let receipt_root = domain_hash(
            "FEE-SPIKE-REPRICING-RECEIPT-PREIMAGE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&preconfirmation_id),
                HashPart::Str(&account_commitment),
                HashPart::Int(repriced_fee_micro_units as i128),
            ],
            32,
        );
        let receipt = RepricingReceipt {
            receipt_id: receipt_id.clone(),
            sequence,
            preconfirmation_id,
            account_commitment,
            shock_id,
            status,
            original_fee_micro_units,
            repriced_fee_micro_units,
            user_cap_micro_units,
            sponsor_absorbed_micro_units: sponsor_absorbed,
            valid_until_height: issued_at_height.saturating_add(self.config.repricing_ttl_blocks),
            issued_at_height,
            receipt_root,
        };
        receipt.validate()?;
        self.counters.next_repricing_receipt =
            self.counters.next_repricing_receipt.saturating_add(1);
        self.repricing_receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn smooth_bridge_exit_fee(
        &mut self,
        exit_batch_id: impl Into<String>,
        monero_height: u64,
        l2_height: u64,
        raw_exit_fee_piconero: u64,
        previous_smoothed_fee_piconero: u64,
        liquidity_provider_root: impl Into<String>,
        exit_manifest_root: impl Into<String>,
    ) -> Result<String> {
        let sequence = self.counters.next_bridge_exit_smoothing;
        let exit_batch_id = exit_batch_id.into();
        let smoothing_id = bridge_exit_smoothing_id(sequence, &exit_batch_id, l2_height);
        let smoothed = smooth_step(
            previous_smoothed_fee_piconero,
            raw_exit_fee_piconero,
            self.config.bridge_exit_max_step_bps,
        );
        let record = BridgeExitFeeSmoothingRecord {
            smoothing_id: smoothing_id.clone(),
            sequence,
            exit_batch_id,
            status: BridgeExitSmoothingStatus::Applied,
            monero_height,
            l2_height,
            raw_exit_fee_piconero,
            smoothed_exit_fee_piconero: smoothed,
            previous_smoothed_fee_piconero,
            max_step_bps: self.config.bridge_exit_max_step_bps,
            smoothing_window_blocks: self.config.exit_smoothing_window_blocks,
            liquidity_provider_root: liquidity_provider_root.into(),
            exit_manifest_root: exit_manifest_root.into(),
        };
        record.validate()?;
        self.counters.next_bridge_exit_smoothing =
            self.counters.next_bridge_exit_smoothing.saturating_add(1);
        self.bridge_exit_smoothing
            .insert(smoothing_id.clone(), record);
        Ok(smoothing_id)
    }

    pub fn mark_nullifier_watched(&mut self, nullifier_root: impl Into<String>) -> Result<()> {
        let nullifier_root = nullifier_root.into();
        require_non_empty("nullifier_root", &nullifier_root)?;
        self.watched_nullifiers.insert(nullifier_root);
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        let config_root = record_root("FEE-SPIKE-CONFIG", &self.config.public_record());
        let counters_root = record_root("FEE-SPIKE-COUNTERS", &self.counters.public_record());
        let shock_root = map_root("FEE-SPIKE-SHOCK", &self.shocks);
        let oracle_sample_root = map_root("FEE-SPIKE-ORACLE-SAMPLE", &self.oracle_samples);
        let sponsor_pool_root = map_root("FEE-SPIKE-SPONSOR-POOL", &self.sponsor_pools);
        let auction_round_root = map_root("FEE-SPIKE-AUCTION-ROUND", &self.auction_rounds);
        let compression_fallback_root = map_root(
            "FEE-SPIKE-COMPRESSION-FALLBACK",
            &self.compression_fallbacks,
        );
        let netting_set_root = map_root("FEE-SPIKE-NETTING-SET", &self.netting_sets);
        let cap_enforcement_root = map_root("FEE-SPIKE-CAP-ENFORCEMENT", &self.cap_enforcements);
        let repricing_receipt_root =
            map_root("FEE-SPIKE-REPRICING-RECEIPT", &self.repricing_receipts);
        let bridge_exit_smoothing_root = map_root(
            "FEE-SPIKE-BRIDGE-EXIT-SMOOTHING",
            &self.bridge_exit_smoothing,
        );
        let watched_nullifier_root =
            set_root("FEE-SPIKE-WATCHED-NULLIFIER", &self.watched_nullifiers);
        let public_event_root = map_root("FEE-SPIKE-PUBLIC-EVENT", &self.public_events);
        let state_preimage = json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config_root": config_root,
            "counters_root": counters_root,
            "shock_root": shock_root,
            "oracle_sample_root": oracle_sample_root,
            "sponsor_pool_root": sponsor_pool_root,
            "auction_round_root": auction_round_root,
            "compression_fallback_root": compression_fallback_root,
            "netting_set_root": netting_set_root,
            "cap_enforcement_root": cap_enforcement_root,
            "repricing_receipt_root": repricing_receipt_root,
            "bridge_exit_smoothing_root": bridge_exit_smoothing_root,
            "watched_nullifier_root": watched_nullifier_root,
            "public_event_root": public_event_root
        });
        let state_root = record_root("FEE-SPIKE-STATE", &state_preimage);
        Roots {
            config_root,
            counters_root,
            shock_root,
            oracle_sample_root,
            sponsor_pool_root,
            auction_round_root,
            compression_fallback_root,
            netting_set_root,
            cap_enforcement_root,
            repricing_receipt_root,
            bridge_exit_smoothing_root,
            watched_nullifier_root,
            public_event_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "oracle_samples": self.oracle_samples.len(),
            "shocks": self.shocks.len(),
            "sponsor_pools": self.sponsor_pools.len(),
            "auction_bids": self.auction_bids.len(),
            "auction_rounds": self.auction_rounds.len(),
            "compression_fallbacks": self.compression_fallbacks.len(),
            "netting_sets": self.netting_sets.len(),
            "cap_enforcements": self.cap_enforcements.len(),
            "repricing_receipts": self.repricing_receipts.len(),
            "bridge_exit_smoothing": self.bridge_exit_smoothing.len(),
            "watched_nullifiers": self.watched_nullifiers.len(),
            "public_events": self.public_events.len()
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn emit_event(
        &mut self,
        kind: ShockKind,
        subject_id: String,
        height: u64,
        severity: ShockSeverity,
    ) -> Result<()> {
        require(
            self.public_events.len() < self.config.max_events,
            "public event limit reached",
        )?;
        let sequence = self.counters.next_public_event;
        let record_root = domain_hash(
            "FEE-SPIKE-PUBLIC-EVENT-SUBJECT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(kind.as_str()),
                HashPart::Str(&subject_id),
                HashPart::Int(height as i128),
            ],
            32,
        );
        let event_id = public_event_id(sequence, kind, &subject_id);
        let mut metadata = BTreeMap::new();
        metadata.insert("lane_family".to_string(), "low_fee_private_l2".to_string());
        metadata.insert("runtime".to_string(), PROTOCOL_VERSION.to_string());
        let event = PublicEvent {
            event_id: event_id.clone(),
            sequence,
            kind,
            subject_id,
            height,
            severity,
            record_root,
            metadata,
        };
        event.validate()?;
        self.counters.next_public_event = self.counters.next_public_event.saturating_add(1);
        self.public_events.insert(event_id, event);
        Ok(())
    }

    fn seed_devnet(&mut self) {
        let baseline = self.record_oracle_sample(
            "devnet-fee-oracle-committee",
            DEVNET_HEIGHT,
            120,
            42_000,
            180,
            15,
            9_700,
            deterministic_label_root("devnet-baseline-oracle"),
        );
        let observed = self.record_oracle_sample(
            "devnet-fee-oracle-committee",
            DEVNET_HEIGHT.saturating_add(6),
            420,
            91_000,
            610,
            27,
            9_300,
            deterministic_label_root("devnet-observed-oracle"),
        );
        let (baseline_id, observed_id) = match (baseline, observed) {
            (Ok(a), Ok(b)) => (a, b),
            _ => return,
        };
        let pool_id = match self.register_sponsor_pool(
            "devnet-sponsor-alpha",
            DEVNET_FEE_ASSET_ID,
            9_000_000,
            700_000,
            DEVNET_HEIGHT,
            deterministic_label_root("devnet-sponsor-refill"),
            deterministic_label_root("devnet-sponsor-credential"),
        ) {
            Ok(id) => id,
            Err(_) => return,
        };
        let shock_id = match self.register_shock(
            ShockKind::DaPrice,
            FeeLaneKind::DataAvailability,
            baseline_id,
            observed_id,
            DEVNET_HEIGHT.saturating_add(6),
            deterministic_label_root("devnet-da-mitigation"),
            deterministic_label_root("devnet-da-note-commitments"),
        ) {
            Ok(id) => id,
            Err(_) => return,
        };
        let bid_a = self.submit_auction_bid(
            "devnet-wallet-a",
            FeeLaneKind::DataAvailability,
            390,
            32,
            22,
            Some(pool_id.clone()),
            deterministic_label_root("devnet-bid-a"),
        );
        let bid_b = self.submit_auction_bid(
            "devnet-wallet-b",
            FeeLaneKind::DataAvailability,
            360,
            24,
            21,
            Some(pool_id.clone()),
            deterministic_label_root("devnet-bid-b"),
        );
        let mut bid_ids = BTreeSet::new();
        if let Ok(id) = bid_a {
            bid_ids.insert(id);
        }
        if let Ok(id) = bid_b {
            bid_ids.insert(id);
        }
        let auction_id = match self.open_auction_round(
            FeeLaneKind::DataAvailability,
            Some(shock_id.clone()),
            DEVNET_HEIGHT.saturating_add(7),
            48,
            bid_ids,
            deterministic_label_root("devnet-auction-clearing-proof"),
        ) {
            Ok(id) => id,
            Err(_) => return,
        };
        let _ = self.clear_auction_round(&auction_id, 360, 650);
        let _ = self.activate_compression_fallback(
            Some(shock_id.clone()),
            FeeLaneKind::DataAvailability,
            CompressionMode::Calldata,
            CompressionMode::Dictionary,
            128_000,
            41_000,
            DEVNET_HEIGHT.saturating_add(8),
            deterministic_label_root("devnet-compression-dictionary"),
            deterministic_label_root("devnet-compression-proof"),
        );
        let lines = vec![
            NettingAssetLine {
                asset_id: DEVNET_FEE_ASSET_ID.to_string(),
                asset_kind: AssetKind::WrappedMonero,
                debit_micro_units: 12_000,
                credit_micro_units: 7_000,
                oracle_rate_micro_units: 1_000_000,
                settlement_priority: 1,
            },
            NettingAssetLine {
                asset_id: DEVNET_STABLE_ASSET_ID.to_string(),
                asset_kind: AssetKind::StableAsset,
                debit_micro_units: 2_000,
                credit_micro_units: 6_500,
                oracle_rate_micro_units: 1_000_000,
                settlement_priority: 2,
            },
            NettingAssetLine {
                asset_id: DEVNET_CREDIT_ASSET_ID.to_string(),
                asset_kind: AssetKind::FeeCredit,
                debit_micro_units: 0,
                credit_micro_units: 900,
                oracle_rate_micro_units: 1_000_000,
                settlement_priority: 3,
            },
        ];
        let _ = self.create_netting_set(
            FeeLaneKind::DataAvailability,
            Some(auction_id),
            Some(pool_id.clone()),
            64,
            self.config.min_privacy_set_size,
            lines,
            600,
            DEVNET_HEIGHT.saturating_add(9),
        );
        let _ = self.enforce_user_fee_cap(
            "devnet-account-commitment-a",
            FeeLaneKind::Preconfirmation,
            1_200,
            900,
            Some(pool_id),
            DEVNET_HEIGHT.saturating_add(10),
            deterministic_label_root("devnet-cap-policy"),
        );
        let _ = self.issue_repricing_receipt(
            "devnet-preconfirmation-a",
            "devnet-account-commitment-a",
            Some(shock_id),
            700,
            1_050,
            200,
            DEVNET_HEIGHT.saturating_add(11),
        );
        let _ = self.smooth_bridge_exit_fee(
            "devnet-exit-batch-a",
            3_200_000,
            DEVNET_HEIGHT.saturating_add(12),
            240_000,
            220_000,
            deterministic_label_root("devnet-exit-lp-root"),
            deterministic_label_root("devnet-exit-manifest"),
        );
        let _ = self.mark_nullifier_watched(deterministic_label_root("devnet-nullifier-watch"));
    }
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for FeeOracleSample {
    fn public_record(&self) -> Value {
        FeeOracleSample::public_record(self)
    }
}

impl PublicRecord for FeeShockEvent {
    fn public_record(&self) -> Value {
        FeeShockEvent::public_record(self)
    }
}

impl PublicRecord for SponsorPoolRecord {
    fn public_record(&self) -> Value {
        SponsorPoolRecord::public_record(self)
    }
}

impl PublicRecord for AuctionRound {
    fn public_record(&self) -> Value {
        AuctionRound::public_record(self)
    }
}

impl PublicRecord for CompressionFallbackRecord {
    fn public_record(&self) -> Value {
        CompressionFallbackRecord::public_record(self)
    }
}

impl PublicRecord for MultiAssetNettingSet {
    fn public_record(&self) -> Value {
        MultiAssetNettingSet::public_record(self)
    }
}

impl PublicRecord for CapEnforcementRecord {
    fn public_record(&self) -> Value {
        CapEnforcementRecord::public_record(self)
    }
}

impl PublicRecord for RepricingReceipt {
    fn public_record(&self) -> Value {
        RepricingReceipt::public_record(self)
    }
}

impl PublicRecord for BridgeExitFeeSmoothingRecord {
    fn public_record(&self) -> Value {
        BridgeExitFeeSmoothingRecord::public_record(self)
    }
}

impl PublicRecord for PublicEvent {
    fn public_record(&self) -> Value {
        PublicEvent::public_record(self)
    }
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_non_empty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must be non-empty"))
    } else {
        Ok(())
    }
}

fn sample_price_for_kind(sample: &FeeOracleSample, kind: ShockKind) -> u64 {
    match kind {
        ShockKind::DaPrice | ShockKind::CalldataCompression | ShockKind::BatchAuction => {
            sample.da_price_micro_units
        }
        ShockKind::MoneroFeeOracle | ShockKind::BridgeExitSmoothing => {
            sample.monero_fee_piconero_per_kb
        }
        ShockKind::ProofMarket | ShockKind::PreconfirmationRepricing => {
            sample.proof_market_micro_units
        }
        ShockKind::SponsorDepletion | ShockKind::MultiAssetNetting | ShockKind::UserFeeCap => {
            sample.l2_base_fee_micro_units
        }
    }
}

fn bps_delta(baseline: u64, observed: u64) -> u64 {
    if baseline == 0 {
        return MAX_BPS;
    }
    observed
        .abs_diff(baseline)
        .saturating_mul(MAX_BPS)
        .saturating_div(baseline)
}

fn severity_for_jump(jump_bps: u64) -> ShockSeverity {
    if jump_bps >= ShockSeverity::Critical.bps_floor() {
        ShockSeverity::Critical
    } else if jump_bps >= ShockSeverity::Severe.bps_floor() {
        ShockSeverity::Severe
    } else if jump_bps >= ShockSeverity::Elevated.bps_floor() {
        ShockSeverity::Elevated
    } else {
        ShockSeverity::Observe
    }
}

fn smooth_step(previous: u64, raw: u64, max_step_bps: u64) -> u64 {
    if previous == 0 {
        return raw;
    }
    let max_step = previous
        .saturating_mul(max_step_bps)
        .saturating_div(MAX_BPS);
    if raw > previous {
        previous.saturating_add(raw.saturating_sub(previous).min(max_step))
    } else {
        previous.saturating_sub(previous.saturating_sub(raw).min(max_step))
    }
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn map_root<T: PublicRecord>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let leaves: Vec<Value> = records
        .iter()
        .map(|(id, record)| {
            json!({
                "id": id,
                "record": record.public_record()
            })
        })
        .collect();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, records: &BTreeSet<String>) -> String {
    let leaves: Vec<Value> = records
        .iter()
        .map(|record| json!({ "value": record, "chain_id": CHAIN_ID }))
        .collect();
    merkle_root(domain, &leaves)
}

fn lines_root(domain: &str, lines: &[NettingAssetLine]) -> String {
    let leaves: Vec<Value> = lines.iter().map(NettingAssetLine::public_record).collect();
    merkle_root(domain, &leaves)
}

pub fn deterministic_label_root(label: &str) -> String {
    domain_hash(
        "FEE-SPIKE-DETERMINISTIC-LABEL",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn oracle_sample_id(
    sequence: u64,
    source_committee_id: &str,
    observed_at_height: u64,
) -> String {
    domain_hash(
        "FEE-SPIKE-ORACLE-SAMPLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(source_committee_id),
            HashPart::Int(observed_at_height as i128),
        ],
        32,
    )
}

pub fn shock_id(
    sequence: u64,
    kind: ShockKind,
    lane: FeeLaneKind,
    detected_at_height: u64,
) -> String {
    domain_hash(
        "FEE-SPIKE-SHOCK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(kind.as_str()),
            HashPart::Str(lane.as_str()),
            HashPart::Int(detected_at_height as i128),
        ],
        32,
    )
}

pub fn sponsor_pool_id(sequence: u64, sponsor_id: &str, fee_asset_id: &str) -> String {
    domain_hash(
        "FEE-SPIKE-SPONSOR-POOL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(sponsor_id),
            HashPart::Str(fee_asset_id),
        ],
        32,
    )
}

pub fn bid_id(
    sequence: u64,
    bidder_id: &str,
    lane: FeeLaneKind,
    max_fee_micro_units: u64,
) -> String {
    domain_hash(
        "FEE-SPIKE-AUCTION-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(bidder_id),
            HashPart::Str(lane.as_str()),
            HashPart::Int(max_fee_micro_units as i128),
        ],
        32,
    )
}

pub fn auction_round_id(sequence: u64, lane: FeeLaneKind, opened_at_height: u64) -> String {
    domain_hash(
        "FEE-SPIKE-AUCTION-ROUND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(lane.as_str()),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn compression_fallback_id(
    sequence: u64,
    lane: FeeLaneKind,
    activated_at_height: u64,
) -> String {
    domain_hash(
        "FEE-SPIKE-COMPRESSION-FALLBACK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(lane.as_str()),
            HashPart::Int(activated_at_height as i128),
        ],
        32,
    )
}

pub fn netting_set_id(sequence: u64, lane: FeeLaneKind, settlement_root: &str) -> String {
    domain_hash(
        "FEE-SPIKE-NETTING-SET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(lane.as_str()),
            HashPart::Str(settlement_root),
        ],
        32,
    )
}

pub fn cap_enforcement_id(
    sequence: u64,
    account_commitment: &str,
    lane: FeeLaneKind,
    enforced_at_height: u64,
) -> String {
    domain_hash(
        "FEE-SPIKE-CAP-ENFORCEMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(account_commitment),
            HashPart::Str(lane.as_str()),
            HashPart::Int(enforced_at_height as i128),
        ],
        32,
    )
}

pub fn repricing_receipt_id(
    sequence: u64,
    preconfirmation_id: &str,
    account_commitment: &str,
) -> String {
    domain_hash(
        "FEE-SPIKE-REPRICING-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(preconfirmation_id),
            HashPart::Str(account_commitment),
        ],
        32,
    )
}

pub fn bridge_exit_smoothing_id(sequence: u64, exit_batch_id: &str, l2_height: u64) -> String {
    domain_hash(
        "FEE-SPIKE-BRIDGE-EXIT-SMOOTHING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(exit_batch_id),
            HashPart::Int(l2_height as i128),
        ],
        32,
    )
}

pub fn public_event_id(sequence: u64, kind: ShockKind, subject_id: &str) -> String {
    domain_hash(
        "FEE-SPIKE-PUBLIC-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
        ],
        32,
    )
}
