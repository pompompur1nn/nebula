use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialLiquidityMiningRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-liquidity-mining-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-liquidity-mining-v1";
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEVNET_HEIGHT: u64 = 752_000;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_MAX_CAMPAIGNS: usize = 262_144;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_MAX_POSITIONS: usize = 8_388_608;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_MAX_EPOCHS: usize = 1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_MAX_CLAIMS: usize = 8_388_608;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_MAX_ATTESTATIONS: usize =
    2_097_152;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize =
    4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_MAX_BATCHES: usize = 1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_MAX_RECEIPTS: usize = 8_388_608;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_MIN_PRIVACY_SET: usize = 512;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_BATCH_PRIVACY_SET: usize = 4_096;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_MAX_CLAIM_FEE_BPS: u64 = 16;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 = 12;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 96;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityCampaignKind {
    AmmPool,
    StableSwap,
    LendingMarket,
    BridgeLiquidity,
    SyntheticMarket,
    PerpetualMarket,
    PredictionMarket,
    Custom,
}

impl LiquidityCampaignKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AmmPool => "amm_pool",
            Self::StableSwap => "stable_swap",
            Self::LendingMarket => "lending_market",
            Self::BridgeLiquidity => "bridge_liquidity",
            Self::SyntheticMarket => "synthetic_market",
            Self::PerpetualMarket => "perpetual_market",
            Self::PredictionMarket => "prediction_market",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignStatus {
    Draft,
    Active,
    Paused,
    Finalizing,
    Settled,
    Cancelled,
}

impl CampaignStatus {
    pub fn accepts_positions(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionStatus {
    Submitted,
    Active,
    EpochLocked,
    Rewarded,
    Withdrawn,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochStatus {
    Open,
    Sealed,
    Scoring,
    Settled,
    Disputed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RewardClaimStatus {
    Submitted,
    Accepted,
    Batched,
    Paid,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Eligible,
    Ineligible,
    SybilRisk,
    LiquidityMoved,
    Escalate,
}

impl AttestationVerdict {
    pub fn allows_reward(self) -> bool {
        matches!(self, Self::Eligible | Self::LiquidityMoved)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReservationStatus {
    Reserved,
    Consumed,
    RebateQueued,
    Refunded,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementBatchStatus {
    Proposed,
    Scoring,
    Settled,
    PartiallySettled,
    Disputed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    CampaignOpened,
    PositionAccepted,
    EpochSealed,
    RewardClaimAccepted,
    BatchSettled,
    RebatePaid,
    CampaignFinalized,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub devnet_height: u64,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub max_campaigns: usize,
    pub max_positions: usize,
    pub max_epochs: usize,
    pub max_claims: usize,
    pub max_attestations: usize,
    pub max_sponsor_reservations: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub min_privacy_set: usize,
    pub batch_privacy_set: usize,
    pub min_pq_security_bits: u16,
    pub max_claim_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub epoch_blocks: u64,
    pub reservation_ttl_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_SCHEMA_VERSION,
            devnet_height: PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEVNET_HEIGHT,
            hash_suite: PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_HASH_SUITE.to_string(),
            pq_auth_suite: PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_PQ_AUTH_SUITE
                .to_string(),
            max_campaigns: PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_MAX_CAMPAIGNS,
            max_positions: PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_MAX_POSITIONS,
            max_epochs: PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_MAX_EPOCHS,
            max_claims: PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_MAX_CLAIMS,
            max_attestations:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_sponsor_reservations:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches: PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts: PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_MAX_RECEIPTS,
            min_privacy_set:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            batch_privacy_set:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_BATCH_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_claim_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_MAX_CLAIM_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            epoch_blocks: PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_EPOCH_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
        }
    }

    pub fn validate(&self) -> PrivateL2ConfidentialLiquidityMiningRuntimeResult<()> {
        if self.chain_id.is_empty()
            || self.protocol_version.is_empty()
            || self.hash_suite.is_empty()
            || self.pq_auth_suite.is_empty()
        {
            return Err("liquidity mining config identifiers cannot be empty".to_string());
        }
        if self.schema_version == 0 || self.devnet_height == 0 {
            return Err("liquidity mining version and devnet height must be positive".to_string());
        }
        if self.max_campaigns == 0
            || self.max_positions == 0
            || self.max_epochs == 0
            || self.max_claims == 0
            || self.max_attestations == 0
            || self.max_sponsor_reservations == 0
            || self.max_batches == 0
            || self.max_receipts == 0
        {
            return Err("liquidity mining capacities must be positive".to_string());
        }
        if self.min_privacy_set == 0 || self.batch_privacy_set < self.min_privacy_set {
            return Err("liquidity mining privacy bounds are invalid".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("liquidity mining pq security target is too low".to_string());
        }
        if self.max_claim_fee_bps > PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_MAX_BPS
            || self.target_rebate_bps > PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_MAX_BPS
        {
            return Err("liquidity mining fee or rebate bps exceeds max".to_string());
        }
        if self.epoch_blocks == 0 || self.reservation_ttl_blocks == 0 {
            return Err("liquidity mining timing windows must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_liquidity_mining_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "devnet_height": self.devnet_height,
            "hash_suite": self.hash_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "max_campaigns": self.max_campaigns,
            "max_positions": self.max_positions,
            "max_epochs": self.max_epochs,
            "max_claims": self.max_claims,
            "max_attestations": self.max_attestations,
            "max_sponsor_reservations": self.max_sponsor_reservations,
            "max_batches": self.max_batches,
            "max_receipts": self.max_receipts,
            "min_privacy_set": self.min_privacy_set,
            "batch_privacy_set": self.batch_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_claim_fee_bps": self.max_claim_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "epoch_blocks": self.epoch_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub campaigns_opened: u64,
    pub positions_submitted: u64,
    pub epochs_opened: u64,
    pub reward_claims_submitted: u64,
    pub eligibility_attestations_posted: u64,
    pub sponsor_reservations_opened: u64,
    pub settlement_batches_built: u64,
    pub receipts_published: u64,
    pub rebates_published: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_liquidity_mining_counters",
            "campaigns_opened": self.campaigns_opened,
            "positions_submitted": self.positions_submitted,
            "epochs_opened": self.epochs_opened,
            "reward_claims_submitted": self.reward_claims_submitted,
            "eligibility_attestations_posted": self.eligibility_attestations_posted,
            "sponsor_reservations_opened": self.sponsor_reservations_opened,
            "settlement_batches_built": self.settlement_batches_built,
            "receipts_published": self.receipts_published,
            "rebates_published": self.rebates_published,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenLiquidityCampaignRequest {
    pub campaign_kind: LiquidityCampaignKind,
    pub sponsor_commitment: String,
    pub reward_asset_id: String,
    pub venue_commitment_root: String,
    pub reward_schedule_root: String,
    pub eligibility_rule_root: String,
    pub starts_at_height: u64,
    pub ends_at_height: u64,
    pub max_reward_bps: u64,
    pub privacy_set_size: usize,
    pub pq_sponsor_authorization_root: String,
}

impl OpenLiquidityCampaignRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "open_liquidity_campaign_request",
            "campaign_kind": self.campaign_kind.as_str(),
            "sponsor_commitment": self.sponsor_commitment,
            "reward_asset_id": self.reward_asset_id,
            "venue_commitment_root": self.venue_commitment_root,
            "reward_schedule_root": self.reward_schedule_root,
            "eligibility_rule_root": self.eligibility_rule_root,
            "starts_at_height": self.starts_at_height,
            "ends_at_height": self.ends_at_height,
            "max_reward_bps": self.max_reward_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_sponsor_authorization_root": self.pq_sponsor_authorization_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitLiquidityPositionRequest {
    pub campaign_id: String,
    pub provider_commitment: String,
    pub encrypted_position_note_root: String,
    pub venue_position_root: String,
    pub liquidity_amount_commitment: String,
    pub duration_commitment: String,
    pub nullifier: String,
    pub privacy_set_size: usize,
    pub pq_position_authorization_root: String,
}

impl SubmitLiquidityPositionRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "submit_liquidity_position_request",
            "campaign_id": self.campaign_id,
            "provider_commitment": self.provider_commitment,
            "encrypted_position_note_root": self.encrypted_position_note_root,
            "venue_position_root": self.venue_position_root,
            "liquidity_amount_commitment": self.liquidity_amount_commitment,
            "duration_commitment": self.duration_commitment,
            "nullifier": self.nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_position_authorization_root": self.pq_position_authorization_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenRewardEpochRequest {
    pub campaign_id: String,
    pub epoch_index: u64,
    pub starts_at_height: u64,
    pub ends_at_height: u64,
    pub reward_bucket_root: String,
    pub scoring_rule_root: String,
    pub pq_epoch_authorization_root: String,
}

impl OpenRewardEpochRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "open_reward_epoch_request",
            "campaign_id": self.campaign_id,
            "epoch_index": self.epoch_index,
            "starts_at_height": self.starts_at_height,
            "ends_at_height": self.ends_at_height,
            "reward_bucket_root": self.reward_bucket_root,
            "scoring_rule_root": self.scoring_rule_root,
            "pq_epoch_authorization_root": self.pq_epoch_authorization_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitRewardClaimRequest {
    pub campaign_id: String,
    pub epoch_id: String,
    pub position_id: String,
    pub claimant_commitment: String,
    pub encrypted_claim_note_root: String,
    pub reward_commitment: String,
    pub claim_nullifier: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: usize,
    pub pq_claim_authorization_root: String,
}

impl SubmitRewardClaimRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "submit_liquidity_reward_claim_request",
            "campaign_id": self.campaign_id,
            "epoch_id": self.epoch_id,
            "position_id": self.position_id,
            "claimant_commitment": self.claimant_commitment,
            "encrypted_claim_note_root": self.encrypted_claim_note_root,
            "reward_commitment": self.reward_commitment,
            "claim_nullifier": self.claim_nullifier,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_claim_authorization_root": self.pq_claim_authorization_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestLiquidityEligibilityRequest {
    pub campaign_id: String,
    pub epoch_id: String,
    pub position_id: String,
    pub attester_commitment: String,
    pub verdict: AttestationVerdict,
    pub venue_evidence_root: String,
    pub sybil_resistance_root: String,
    pub pq_attestation_root: String,
    pub min_pq_security_bits: u16,
}

impl AttestLiquidityEligibilityRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "attest_liquidity_eligibility_request",
            "campaign_id": self.campaign_id,
            "epoch_id": self.epoch_id,
            "position_id": self.position_id,
            "attester_commitment": self.attester_commitment,
            "verdict": format!("{:?}", self.verdict).to_lowercase(),
            "venue_evidence_root": self.venue_evidence_root,
            "sybil_resistance_root": self.sybil_resistance_root,
            "pq_attestation_root": self.pq_attestation_root,
            "min_pq_security_bits": self.min_pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveLiquidityClaimSponsorRequest {
    pub campaign_id: String,
    pub claim_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub max_fee_bps: u64,
    pub coverage_bps: u64,
    pub expires_at_height: u64,
    pub pq_sponsor_authorization_root: String,
}

impl ReserveLiquidityClaimSponsorRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_liquidity_claim_sponsor_request",
            "campaign_id": self.campaign_id,
            "claim_id": self.claim_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_bps": self.max_fee_bps,
            "coverage_bps": self.coverage_bps,
            "expires_at_height": self.expires_at_height,
            "pq_sponsor_authorization_root": self.pq_sponsor_authorization_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildRewardSettlementBatchRequest {
    pub campaign_id: String,
    pub epoch_id: String,
    pub claim_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub scoring_root: String,
    pub encrypted_distribution_root: String,
    pub settlement_proof_root: String,
    pub pq_batch_authorization_root: String,
    pub batch_privacy_set_size: usize,
}

impl BuildRewardSettlementBatchRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "build_reward_settlement_batch_request",
            "campaign_id": self.campaign_id,
            "epoch_id": self.epoch_id,
            "claim_ids": self.claim_ids,
            "attestation_ids": self.attestation_ids,
            "reservation_ids": self.reservation_ids,
            "scoring_root": self.scoring_root,
            "encrypted_distribution_root": self.encrypted_distribution_root,
            "settlement_proof_root": self.settlement_proof_root,
            "pq_batch_authorization_root": self.pq_batch_authorization_root,
            "batch_privacy_set_size": self.batch_privacy_set_size,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishLiquidityMiningReceiptRequest {
    pub campaign_id: String,
    pub epoch_id: String,
    pub batch_id: String,
    pub claim_id: Option<String>,
    pub receipt_kind: ReceiptKind,
    pub recipient_commitment: String,
    pub settlement_root: String,
    pub fee_charged_bps: u64,
    pub rebate_bps: u64,
    pub pq_receipt_root: String,
}

impl PublishLiquidityMiningReceiptRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "publish_liquidity_mining_receipt_request",
            "campaign_id": self.campaign_id,
            "epoch_id": self.epoch_id,
            "batch_id": self.batch_id,
            "claim_id": self.claim_id,
            "receipt_kind": format!("{:?}", self.receipt_kind).to_lowercase(),
            "recipient_commitment": self.recipient_commitment,
            "settlement_root": self.settlement_root,
            "fee_charged_bps": self.fee_charged_bps,
            "rebate_bps": self.rebate_bps,
            "pq_receipt_root": self.pq_receipt_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishLiquidityRebateRequest {
    pub campaign_id: String,
    pub reservation_id: String,
    pub receipt_id: String,
    pub sponsor_commitment: String,
    pub rebate_note_root: String,
    pub rebate_bps: u64,
    pub pq_rebate_root: String,
}

impl PublishLiquidityRebateRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "publish_liquidity_rebate_request",
            "campaign_id": self.campaign_id,
            "reservation_id": self.reservation_id,
            "receipt_id": self.receipt_id,
            "sponsor_commitment": self.sponsor_commitment,
            "rebate_note_root": self.rebate_note_root,
            "rebate_bps": self.rebate_bps,
            "pq_rebate_root": self.pq_rebate_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityCampaignRecord {
    pub campaign_id: String,
    pub request: OpenLiquidityCampaignRequest,
    pub status: CampaignStatus,
    pub created_sequence: u64,
    pub epoch_ids: Vec<String>,
}

impl LiquidityCampaignRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_liquidity_campaign",
            "campaign_id": self.campaign_id,
            "request": self.request.public_record(),
            "status": format!("{:?}", self.status).to_lowercase(),
            "created_sequence": self.created_sequence,
            "epoch_ids": self.epoch_ids,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityPositionRecord {
    pub position_id: String,
    pub request: SubmitLiquidityPositionRequest,
    pub status: PositionStatus,
    pub created_sequence: u64,
}

impl LiquidityPositionRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_liquidity_position",
            "position_id": self.position_id,
            "request": self.request.public_record(),
            "status": format!("{:?}", self.status).to_lowercase(),
            "created_sequence": self.created_sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RewardEpochRecord {
    pub epoch_id: String,
    pub request: OpenRewardEpochRequest,
    pub status: EpochStatus,
    pub created_sequence: u64,
}

impl RewardEpochRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_liquidity_reward_epoch",
            "epoch_id": self.epoch_id,
            "request": self.request.public_record(),
            "status": format!("{:?}", self.status).to_lowercase(),
            "created_sequence": self.created_sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RewardClaimRecord {
    pub claim_id: String,
    pub request: SubmitRewardClaimRequest,
    pub status: RewardClaimStatus,
    pub created_sequence: u64,
    pub batch_id: Option<String>,
}

impl RewardClaimRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_liquidity_reward_claim",
            "claim_id": self.claim_id,
            "request": self.request.public_record(),
            "status": format!("{:?}", self.status).to_lowercase(),
            "created_sequence": self.created_sequence,
            "batch_id": self.batch_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EligibilityAttestationRecord {
    pub attestation_id: String,
    pub request: AttestLiquidityEligibilityRequest,
    pub created_sequence: u64,
}

impl EligibilityAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_liquidity_eligibility_attestation",
            "attestation_id": self.attestation_id,
            "request": self.request.public_record(),
            "created_sequence": self.created_sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquiditySponsorReservationRecord {
    pub reservation_id: String,
    pub request: ReserveLiquidityClaimSponsorRequest,
    pub status: SponsorReservationStatus,
    pub created_sequence: u64,
    pub consumed_by_batch_id: Option<String>,
}

impl LiquiditySponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_liquidity_sponsor_reservation",
            "reservation_id": self.reservation_id,
            "request": self.request.public_record(),
            "status": format!("{:?}", self.status).to_lowercase(),
            "created_sequence": self.created_sequence,
            "consumed_by_batch_id": self.consumed_by_batch_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RewardSettlementBatchRecord {
    pub batch_id: String,
    pub request: BuildRewardSettlementBatchRequest,
    pub status: SettlementBatchStatus,
    pub created_sequence: u64,
}

impl RewardSettlementBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_liquidity_reward_batch",
            "batch_id": self.batch_id,
            "request": self.request.public_record(),
            "status": format!("{:?}", self.status).to_lowercase(),
            "created_sequence": self.created_sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityMiningReceiptRecord {
    pub receipt_id: String,
    pub request: PublishLiquidityMiningReceiptRequest,
    pub created_sequence: u64,
}

impl LiquidityMiningReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_liquidity_mining_receipt",
            "receipt_id": self.receipt_id,
            "request": self.request.public_record(),
            "created_sequence": self.created_sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityRebateRecord {
    pub rebate_id: String,
    pub request: PublishLiquidityRebateRequest,
    pub created_sequence: u64,
}

impl LiquidityRebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_liquidity_rebate",
            "rebate_id": self.rebate_id,
            "request": self.request.public_record(),
            "created_sequence": self.created_sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub campaign_root: String,
    pub position_root: String,
    pub epoch_root: String,
    pub claim_root: String,
    pub attestation_root: String,
    pub sponsor_reservation_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub nullifier_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_liquidity_mining_roots",
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "campaign_root": self.campaign_root,
            "position_root": self.position_root,
            "epoch_root": self.epoch_root,
            "claim_root": self.claim_root,
            "attestation_root": self.attestation_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "nullifier_root": self.nullifier_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub campaigns: BTreeMap<String, LiquidityCampaignRecord>,
    pub positions: BTreeMap<String, LiquidityPositionRecord>,
    pub epochs: BTreeMap<String, RewardEpochRecord>,
    pub reward_claims: BTreeMap<String, RewardClaimRecord>,
    pub eligibility_attestations: BTreeMap<String, EligibilityAttestationRecord>,
    pub sponsor_reservations: BTreeMap<String, LiquiditySponsorReservationRecord>,
    pub settlement_batches: BTreeMap<String, RewardSettlementBatchRecord>,
    pub receipts: BTreeMap<String, LiquidityMiningReceiptRecord>,
    pub rebates: BTreeMap<String, LiquidityRebateRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateL2ConfidentialLiquidityMiningRuntimeResult<Self> {
        Self::new(Config::devnet())
    }

    pub fn new(config: Config) -> PrivateL2ConfidentialLiquidityMiningRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            campaigns: BTreeMap::new(),
            positions: BTreeMap::new(),
            epochs: BTreeMap::new(),
            reward_claims: BTreeMap::new(),
            eligibility_attestations: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn open_campaign(
        &mut self,
        request: OpenLiquidityCampaignRequest,
    ) -> PrivateL2ConfidentialLiquidityMiningRuntimeResult<String> {
        self.require_campaign_capacity()?;
        require_nonempty("sponsor_commitment", &request.sponsor_commitment)?;
        require_nonempty("reward_asset_id", &request.reward_asset_id)?;
        require_nonempty("venue_commitment_root", &request.venue_commitment_root)?;
        require_nonempty("reward_schedule_root", &request.reward_schedule_root)?;
        require_nonempty("eligibility_rule_root", &request.eligibility_rule_root)?;
        require_nonempty(
            "pq_sponsor_authorization_root",
            &request.pq_sponsor_authorization_root,
        )?;
        if request.starts_at_height >= request.ends_at_height {
            return Err("liquidity campaign height window is invalid".to_string());
        }
        if request.max_reward_bps > PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_MAX_BPS {
            return Err("liquidity campaign reward bps exceeds max".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set {
            return Err("liquidity campaign privacy set is too small".to_string());
        }
        let sequence = self.counters.campaigns_opened.saturating_add(1);
        let campaign_id = liquidity_campaign_id(&request, sequence);
        if self.campaigns.contains_key(&campaign_id) {
            return Err("liquidity campaign id collision".to_string());
        }
        let record = LiquidityCampaignRecord {
            campaign_id: campaign_id.clone(),
            request,
            status: CampaignStatus::Active,
            created_sequence: sequence,
            epoch_ids: Vec::new(),
        };
        self.campaigns.insert(campaign_id.clone(), record);
        self.counters.campaigns_opened = sequence;
        Ok(campaign_id)
    }

    pub fn submit_position(
        &mut self,
        request: SubmitLiquidityPositionRequest,
    ) -> PrivateL2ConfidentialLiquidityMiningRuntimeResult<String> {
        self.require_position_capacity()?;
        require_nonempty("campaign_id", &request.campaign_id)?;
        require_nonempty("provider_commitment", &request.provider_commitment)?;
        require_nonempty(
            "encrypted_position_note_root",
            &request.encrypted_position_note_root,
        )?;
        require_nonempty("venue_position_root", &request.venue_position_root)?;
        require_nonempty(
            "liquidity_amount_commitment",
            &request.liquidity_amount_commitment,
        )?;
        require_nonempty("duration_commitment", &request.duration_commitment)?;
        require_nonempty("nullifier", &request.nullifier)?;
        require_nonempty(
            "pq_position_authorization_root",
            &request.pq_position_authorization_root,
        )?;
        if self.consumed_nullifiers.contains(&request.nullifier) {
            return Err("liquidity position nullifier already consumed".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set {
            return Err("liquidity position privacy set is too small".to_string());
        }
        let campaign = self
            .campaigns
            .get(&request.campaign_id)
            .ok_or_else(|| "liquidity campaign not found".to_string())?;
        if !campaign.status.accepts_positions() {
            return Err("liquidity campaign does not accept positions".to_string());
        }
        let sequence = self.counters.positions_submitted.saturating_add(1);
        let position_id = liquidity_position_id(&request, sequence);
        if self.positions.contains_key(&position_id) {
            return Err("liquidity position id collision".to_string());
        }
        let nullifier = request.nullifier.clone();
        let record = LiquidityPositionRecord {
            position_id: position_id.clone(),
            request,
            status: PositionStatus::Active,
            created_sequence: sequence,
        };
        self.consumed_nullifiers.insert(nullifier);
        self.positions.insert(position_id.clone(), record);
        self.counters.positions_submitted = sequence;
        Ok(position_id)
    }

    pub fn open_epoch(
        &mut self,
        request: OpenRewardEpochRequest,
    ) -> PrivateL2ConfidentialLiquidityMiningRuntimeResult<String> {
        self.require_epoch_capacity()?;
        require_nonempty("campaign_id", &request.campaign_id)?;
        require_nonempty("reward_bucket_root", &request.reward_bucket_root)?;
        require_nonempty("scoring_rule_root", &request.scoring_rule_root)?;
        require_nonempty(
            "pq_epoch_authorization_root",
            &request.pq_epoch_authorization_root,
        )?;
        if request.starts_at_height >= request.ends_at_height {
            return Err("liquidity reward epoch height window is invalid".to_string());
        }
        let campaign = self
            .campaigns
            .get_mut(&request.campaign_id)
            .ok_or_else(|| "liquidity campaign not found".to_string())?;
        if !campaign.status.accepts_positions() {
            return Err("liquidity campaign cannot open reward epochs".to_string());
        }
        let sequence = self.counters.epochs_opened.saturating_add(1);
        let epoch_id = reward_epoch_id(&request, sequence);
        if self.epochs.contains_key(&epoch_id) || campaign.epoch_ids.contains(&epoch_id) {
            return Err("liquidity reward epoch id collision".to_string());
        }
        let record = RewardEpochRecord {
            epoch_id: epoch_id.clone(),
            request,
            status: EpochStatus::Open,
            created_sequence: sequence,
        };
        campaign.epoch_ids.push(epoch_id.clone());
        self.epochs.insert(epoch_id.clone(), record);
        self.counters.epochs_opened = sequence;
        Ok(epoch_id)
    }

    pub fn submit_reward_claim(
        &mut self,
        request: SubmitRewardClaimRequest,
    ) -> PrivateL2ConfidentialLiquidityMiningRuntimeResult<String> {
        self.require_claim_capacity()?;
        require_nonempty("campaign_id", &request.campaign_id)?;
        require_nonempty("epoch_id", &request.epoch_id)?;
        require_nonempty("position_id", &request.position_id)?;
        require_nonempty("claimant_commitment", &request.claimant_commitment)?;
        require_nonempty(
            "encrypted_claim_note_root",
            &request.encrypted_claim_note_root,
        )?;
        require_nonempty("reward_commitment", &request.reward_commitment)?;
        require_nonempty("claim_nullifier", &request.claim_nullifier)?;
        require_nonempty(
            "pq_claim_authorization_root",
            &request.pq_claim_authorization_root,
        )?;
        if request.max_fee_bps > self.config.max_claim_fee_bps {
            return Err("liquidity reward claim fee exceeds configured max".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set {
            return Err("liquidity reward claim privacy set is too small".to_string());
        }
        if self.consumed_nullifiers.contains(&request.claim_nullifier) {
            return Err("liquidity reward claim nullifier already consumed".to_string());
        }
        let epoch = self
            .epochs
            .get(&request.epoch_id)
            .ok_or_else(|| "liquidity reward epoch not found".to_string())?;
        if epoch.request.campaign_id != request.campaign_id {
            return Err("liquidity reward epoch belongs to another campaign".to_string());
        }
        if !matches!(epoch.status, EpochStatus::Open | EpochStatus::Sealed) {
            return Err("liquidity reward epoch is not claimable".to_string());
        }
        let position = self
            .positions
            .get(&request.position_id)
            .ok_or_else(|| "liquidity position not found".to_string())?;
        if position.request.campaign_id != request.campaign_id {
            return Err("liquidity position belongs to another campaign".to_string());
        }
        if position.status != PositionStatus::Active {
            return Err("liquidity position is not rewardable".to_string());
        }
        let sequence = self.counters.reward_claims_submitted.saturating_add(1);
        let claim_id = liquidity_reward_claim_id(&request, sequence);
        if self.reward_claims.contains_key(&claim_id) {
            return Err("liquidity reward claim id collision".to_string());
        }
        let nullifier = request.claim_nullifier.clone();
        let record = RewardClaimRecord {
            claim_id: claim_id.clone(),
            request,
            status: RewardClaimStatus::Accepted,
            created_sequence: sequence,
            batch_id: None,
        };
        self.consumed_nullifiers.insert(nullifier);
        self.reward_claims.insert(claim_id.clone(), record);
        self.counters.reward_claims_submitted = sequence;
        Ok(claim_id)
    }

    pub fn attest_eligibility(
        &mut self,
        request: AttestLiquidityEligibilityRequest,
    ) -> PrivateL2ConfidentialLiquidityMiningRuntimeResult<String> {
        self.require_attestation_capacity()?;
        require_nonempty("campaign_id", &request.campaign_id)?;
        require_nonempty("epoch_id", &request.epoch_id)?;
        require_nonempty("position_id", &request.position_id)?;
        require_nonempty("attester_commitment", &request.attester_commitment)?;
        require_nonempty("venue_evidence_root", &request.venue_evidence_root)?;
        require_nonempty("sybil_resistance_root", &request.sybil_resistance_root)?;
        require_nonempty("pq_attestation_root", &request.pq_attestation_root)?;
        if request.min_pq_security_bits < self.config.min_pq_security_bits {
            return Err("liquidity eligibility pq security below target".to_string());
        }
        if !request.verdict.allows_reward() {
            if let Some(position) = self.positions.get_mut(&request.position_id) {
                position.status = PositionStatus::Rejected;
            }
        }
        let epoch = self
            .epochs
            .get(&request.epoch_id)
            .ok_or_else(|| "liquidity reward epoch not found".to_string())?;
        if epoch.request.campaign_id != request.campaign_id {
            return Err("liquidity eligibility epoch belongs to another campaign".to_string());
        }
        let position = self
            .positions
            .get(&request.position_id)
            .ok_or_else(|| "liquidity position not found".to_string())?;
        if position.request.campaign_id != request.campaign_id {
            return Err("liquidity eligibility position belongs to another campaign".to_string());
        }
        let sequence = self
            .counters
            .eligibility_attestations_posted
            .saturating_add(1);
        let attestation_id = liquidity_eligibility_attestation_id(&request, sequence);
        if self.eligibility_attestations.contains_key(&attestation_id) {
            return Err("liquidity eligibility attestation id collision".to_string());
        }
        let record = EligibilityAttestationRecord {
            attestation_id: attestation_id.clone(),
            request,
            created_sequence: sequence,
        };
        self.eligibility_attestations
            .insert(attestation_id.clone(), record);
        self.counters.eligibility_attestations_posted = sequence;
        Ok(attestation_id)
    }

    pub fn reserve_sponsor(
        &mut self,
        request: ReserveLiquidityClaimSponsorRequest,
    ) -> PrivateL2ConfidentialLiquidityMiningRuntimeResult<String> {
        self.require_reservation_capacity()?;
        require_nonempty("campaign_id", &request.campaign_id)?;
        require_nonempty("claim_id", &request.claim_id)?;
        require_nonempty("sponsor_commitment", &request.sponsor_commitment)?;
        require_nonempty("fee_asset_id", &request.fee_asset_id)?;
        require_nonempty(
            "pq_sponsor_authorization_root",
            &request.pq_sponsor_authorization_root,
        )?;
        if request.max_fee_bps > self.config.max_claim_fee_bps {
            return Err("liquidity sponsor fee exceeds configured max".to_string());
        }
        if request.coverage_bps > PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_MAX_BPS {
            return Err("liquidity sponsor coverage exceeds max".to_string());
        }
        let claim = self
            .reward_claims
            .get(&request.claim_id)
            .ok_or_else(|| "liquidity reward claim not found".to_string())?;
        if claim.request.campaign_id != request.campaign_id {
            return Err("liquidity sponsor claim belongs to another campaign".to_string());
        }
        if claim.status != RewardClaimStatus::Accepted {
            return Err("liquidity reward claim is not sponsorable".to_string());
        }
        let sequence = self.counters.sponsor_reservations_opened.saturating_add(1);
        let reservation_id = liquidity_sponsor_reservation_id(&request, sequence);
        if self.sponsor_reservations.contains_key(&reservation_id) {
            return Err("liquidity sponsor reservation id collision".to_string());
        }
        let record = LiquiditySponsorReservationRecord {
            reservation_id: reservation_id.clone(),
            request,
            status: SponsorReservationStatus::Reserved,
            created_sequence: sequence,
            consumed_by_batch_id: None,
        };
        self.sponsor_reservations
            .insert(reservation_id.clone(), record);
        self.counters.sponsor_reservations_opened = sequence;
        Ok(reservation_id)
    }

    pub fn build_settlement_batch(
        &mut self,
        request: BuildRewardSettlementBatchRequest,
    ) -> PrivateL2ConfidentialLiquidityMiningRuntimeResult<String> {
        self.require_batch_capacity()?;
        require_nonempty("campaign_id", &request.campaign_id)?;
        require_nonempty("epoch_id", &request.epoch_id)?;
        require_nonempty("scoring_root", &request.scoring_root)?;
        require_nonempty(
            "encrypted_distribution_root",
            &request.encrypted_distribution_root,
        )?;
        require_nonempty("settlement_proof_root", &request.settlement_proof_root)?;
        require_nonempty(
            "pq_batch_authorization_root",
            &request.pq_batch_authorization_root,
        )?;
        require_unique("liquidity claim ids", &request.claim_ids)?;
        require_unique("liquidity attestation ids", &request.attestation_ids)?;
        require_unique("liquidity reservation ids", &request.reservation_ids)?;
        if request.claim_ids.is_empty() {
            return Err("liquidity settlement batch requires claims".to_string());
        }
        if request.batch_privacy_set_size < self.config.batch_privacy_set {
            return Err("liquidity settlement batch privacy set is too small".to_string());
        }
        let epoch = self
            .epochs
            .get_mut(&request.epoch_id)
            .ok_or_else(|| "liquidity reward epoch not found".to_string())?;
        if epoch.request.campaign_id != request.campaign_id {
            return Err("liquidity settlement epoch belongs to another campaign".to_string());
        }
        if !matches!(epoch.status, EpochStatus::Open | EpochStatus::Sealed) {
            return Err("liquidity settlement epoch is not batchable".to_string());
        }
        for claim_id in &request.claim_ids {
            let claim = self
                .reward_claims
                .get(claim_id)
                .ok_or_else(|| format!("liquidity reward claim {claim_id} not found"))?;
            if claim.request.campaign_id != request.campaign_id
                || claim.request.epoch_id != request.epoch_id
            {
                return Err("liquidity reward claim belongs to another scope".to_string());
            }
            if claim.status != RewardClaimStatus::Accepted {
                return Err("liquidity reward claim is not batchable".to_string());
            }
        }
        for attestation_id in &request.attestation_ids {
            let attestation = self
                .eligibility_attestations
                .get(attestation_id)
                .ok_or_else(|| format!("liquidity attestation {attestation_id} not found"))?;
            if attestation.request.campaign_id != request.campaign_id
                || attestation.request.epoch_id != request.epoch_id
            {
                return Err("liquidity attestation belongs to another scope".to_string());
            }
        }
        for reservation_id in &request.reservation_ids {
            let reservation = self
                .sponsor_reservations
                .get(reservation_id)
                .ok_or_else(|| format!("liquidity reservation {reservation_id} not found"))?;
            if reservation.request.campaign_id != request.campaign_id {
                return Err("liquidity sponsor reservation belongs to another campaign".to_string());
            }
            if reservation.status != SponsorReservationStatus::Reserved {
                return Err("liquidity sponsor reservation is not active".to_string());
            }
        }
        let sequence = self.counters.settlement_batches_built.saturating_add(1);
        let batch_id = reward_settlement_batch_id(&request, sequence);
        if self.settlement_batches.contains_key(&batch_id) {
            return Err("liquidity settlement batch id collision".to_string());
        }
        epoch.status = EpochStatus::Scoring;
        for claim_id in &request.claim_ids {
            if let Some(claim) = self.reward_claims.get_mut(claim_id) {
                claim.status = RewardClaimStatus::Batched;
                claim.batch_id = Some(batch_id.clone());
            }
        }
        for reservation_id in &request.reservation_ids {
            if let Some(reservation) = self.sponsor_reservations.get_mut(reservation_id) {
                reservation.status = SponsorReservationStatus::Consumed;
                reservation.consumed_by_batch_id = Some(batch_id.clone());
            }
        }
        let record = RewardSettlementBatchRecord {
            batch_id: batch_id.clone(),
            request,
            status: SettlementBatchStatus::Scoring,
            created_sequence: sequence,
        };
        self.settlement_batches.insert(batch_id.clone(), record);
        self.counters.settlement_batches_built = sequence;
        Ok(batch_id)
    }

    pub fn publish_receipt(
        &mut self,
        request: PublishLiquidityMiningReceiptRequest,
    ) -> PrivateL2ConfidentialLiquidityMiningRuntimeResult<String> {
        self.require_receipt_capacity()?;
        require_nonempty("campaign_id", &request.campaign_id)?;
        require_nonempty("epoch_id", &request.epoch_id)?;
        require_nonempty("batch_id", &request.batch_id)?;
        require_nonempty("recipient_commitment", &request.recipient_commitment)?;
        require_nonempty("settlement_root", &request.settlement_root)?;
        require_nonempty("pq_receipt_root", &request.pq_receipt_root)?;
        if request.fee_charged_bps > self.config.max_claim_fee_bps {
            return Err("liquidity receipt fee exceeds configured max".to_string());
        }
        if request.rebate_bps > PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_MAX_BPS {
            return Err("liquidity receipt rebate exceeds max".to_string());
        }
        let batch = self
            .settlement_batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| "liquidity settlement batch not found".to_string())?;
        if batch.request.campaign_id != request.campaign_id
            || batch.request.epoch_id != request.epoch_id
        {
            return Err("liquidity receipt batch belongs to another scope".to_string());
        }
        batch.status = SettlementBatchStatus::Settled;
        if let Some(epoch) = self.epochs.get_mut(&request.epoch_id) {
            epoch.status = EpochStatus::Settled;
        }
        for claim_id in &batch.request.claim_ids {
            if let Some(claim) = self.reward_claims.get_mut(claim_id) {
                claim.status = RewardClaimStatus::Paid;
            }
        }
        let sequence = self.counters.receipts_published.saturating_add(1);
        let receipt_id = liquidity_mining_receipt_id(&request, sequence);
        if self.receipts.contains_key(&receipt_id) {
            return Err("liquidity mining receipt id collision".to_string());
        }
        let record = LiquidityMiningReceiptRecord {
            receipt_id: receipt_id.clone(),
            request,
            created_sequence: sequence,
        };
        self.receipts.insert(receipt_id.clone(), record);
        self.counters.receipts_published = sequence;
        Ok(receipt_id)
    }

    pub fn publish_rebate(
        &mut self,
        request: PublishLiquidityRebateRequest,
    ) -> PrivateL2ConfidentialLiquidityMiningRuntimeResult<String> {
        self.require_receipt_capacity()?;
        require_nonempty("campaign_id", &request.campaign_id)?;
        require_nonempty("reservation_id", &request.reservation_id)?;
        require_nonempty("receipt_id", &request.receipt_id)?;
        require_nonempty("sponsor_commitment", &request.sponsor_commitment)?;
        require_nonempty("rebate_note_root", &request.rebate_note_root)?;
        require_nonempty("pq_rebate_root", &request.pq_rebate_root)?;
        if request.rebate_bps > self.config.target_rebate_bps {
            return Err("liquidity rebate exceeds runtime target".to_string());
        }
        if !self.receipts.contains_key(&request.receipt_id) {
            return Err("liquidity rebate receipt not found".to_string());
        }
        let reservation = self
            .sponsor_reservations
            .get_mut(&request.reservation_id)
            .ok_or_else(|| "liquidity sponsor reservation not found".to_string())?;
        if reservation.request.campaign_id != request.campaign_id {
            return Err("liquidity rebate reservation belongs to another campaign".to_string());
        }
        reservation.status = SponsorReservationStatus::RebateQueued;
        let sequence = self.counters.rebates_published.saturating_add(1);
        let rebate_id = liquidity_rebate_id(&request, sequence);
        if self.rebates.contains_key(&rebate_id) {
            return Err("liquidity rebate id collision".to_string());
        }
        let record = LiquidityRebateRecord {
            rebate_id: rebate_id.clone(),
            request,
            created_sequence: sequence,
        };
        self.rebates.insert(rebate_id.clone(), record);
        self.counters.rebates_published = sequence;
        Ok(rebate_id)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: root_from_record(
                "PRIVATE-L2-CONFIDENTIAL-LIQUIDITY-MINING-CONFIG",
                &self.config.public_record(),
            ),
            counters_root: root_from_record(
                "PRIVATE-L2-CONFIDENTIAL-LIQUIDITY-MINING-COUNTERS",
                &self.counters.public_record(),
            ),
            campaign_root: record_root(
                "PRIVATE-L2-CONFIDENTIAL-LIQUIDITY-MINING-CAMPAIGNS",
                self.campaigns
                    .values()
                    .map(LiquidityCampaignRecord::public_record),
            ),
            position_root: record_root(
                "PRIVATE-L2-CONFIDENTIAL-LIQUIDITY-MINING-POSITIONS",
                self.positions
                    .values()
                    .map(LiquidityPositionRecord::public_record),
            ),
            epoch_root: record_root(
                "PRIVATE-L2-CONFIDENTIAL-LIQUIDITY-MINING-EPOCHS",
                self.epochs.values().map(RewardEpochRecord::public_record),
            ),
            claim_root: record_root(
                "PRIVATE-L2-CONFIDENTIAL-LIQUIDITY-MINING-CLAIMS",
                self.reward_claims
                    .values()
                    .map(RewardClaimRecord::public_record),
            ),
            attestation_root: record_root(
                "PRIVATE-L2-CONFIDENTIAL-LIQUIDITY-MINING-ATTESTATIONS",
                self.eligibility_attestations
                    .values()
                    .map(EligibilityAttestationRecord::public_record),
            ),
            sponsor_reservation_root: record_root(
                "PRIVATE-L2-CONFIDENTIAL-LIQUIDITY-MINING-SPONSOR-RESERVATIONS",
                self.sponsor_reservations
                    .values()
                    .map(LiquiditySponsorReservationRecord::public_record),
            ),
            batch_root: record_root(
                "PRIVATE-L2-CONFIDENTIAL-LIQUIDITY-MINING-BATCHES",
                self.settlement_batches
                    .values()
                    .map(RewardSettlementBatchRecord::public_record),
            ),
            receipt_root: record_root(
                "PRIVATE-L2-CONFIDENTIAL-LIQUIDITY-MINING-RECEIPTS",
                self.receipts
                    .values()
                    .map(LiquidityMiningReceiptRecord::public_record),
            ),
            rebate_root: record_root(
                "PRIVATE-L2-CONFIDENTIAL-LIQUIDITY-MINING-REBATES",
                self.rebates
                    .values()
                    .map(LiquidityRebateRecord::public_record),
            ),
            nullifier_root: id_list_root(
                "PRIVATE-L2-CONFIDENTIAL-LIQUIDITY-MINING-NULLIFIERS",
                self.consumed_nullifiers.iter(),
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_liquidity_mining_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn require_campaign_capacity(&self) -> PrivateL2ConfidentialLiquidityMiningRuntimeResult<()> {
        if self.campaigns.len() >= self.config.max_campaigns {
            return Err("liquidity campaign capacity exhausted".to_string());
        }
        Ok(())
    }

    fn require_position_capacity(&self) -> PrivateL2ConfidentialLiquidityMiningRuntimeResult<()> {
        if self.positions.len() >= self.config.max_positions {
            return Err("liquidity position capacity exhausted".to_string());
        }
        Ok(())
    }

    fn require_epoch_capacity(&self) -> PrivateL2ConfidentialLiquidityMiningRuntimeResult<()> {
        if self.epochs.len() >= self.config.max_epochs {
            return Err("liquidity epoch capacity exhausted".to_string());
        }
        Ok(())
    }

    fn require_claim_capacity(&self) -> PrivateL2ConfidentialLiquidityMiningRuntimeResult<()> {
        if self.reward_claims.len() >= self.config.max_claims {
            return Err("liquidity reward claim capacity exhausted".to_string());
        }
        Ok(())
    }

    fn require_attestation_capacity(
        &self,
    ) -> PrivateL2ConfidentialLiquidityMiningRuntimeResult<()> {
        if self.eligibility_attestations.len() >= self.config.max_attestations {
            return Err("liquidity eligibility attestation capacity exhausted".to_string());
        }
        Ok(())
    }

    fn require_reservation_capacity(
        &self,
    ) -> PrivateL2ConfidentialLiquidityMiningRuntimeResult<()> {
        if self.sponsor_reservations.len() >= self.config.max_sponsor_reservations {
            return Err("liquidity sponsor reservation capacity exhausted".to_string());
        }
        Ok(())
    }

    fn require_batch_capacity(&self) -> PrivateL2ConfidentialLiquidityMiningRuntimeResult<()> {
        if self.settlement_batches.len() >= self.config.max_batches {
            return Err("liquidity settlement batch capacity exhausted".to_string());
        }
        Ok(())
    }

    fn require_receipt_capacity(&self) -> PrivateL2ConfidentialLiquidityMiningRuntimeResult<()> {
        if self.receipts.len() >= self.config.max_receipts {
            return Err("liquidity receipt capacity exhausted".to_string());
        }
        Ok(())
    }
}

pub type Runtime = State;

pub fn liquidity_campaign_id(request: &OpenLiquidityCampaignRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-LIQUIDITY-CAMPAIGN-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn liquidity_position_id(request: &SubmitLiquidityPositionRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-LIQUIDITY-POSITION-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn reward_epoch_id(request: &OpenRewardEpochRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-LIQUIDITY-REWARD-EPOCH-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn liquidity_reward_claim_id(request: &SubmitRewardClaimRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-LIQUIDITY-REWARD-CLAIM-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn liquidity_eligibility_attestation_id(
    request: &AttestLiquidityEligibilityRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-LIQUIDITY-ELIGIBILITY-ATTESTATION-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn liquidity_sponsor_reservation_id(
    request: &ReserveLiquidityClaimSponsorRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-LIQUIDITY-SPONSOR-RESERVATION-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn reward_settlement_batch_id(
    request: &BuildRewardSettlementBatchRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-LIQUIDITY-REWARD-BATCH-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn liquidity_mining_receipt_id(
    request: &PublishLiquidityMiningReceiptRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-LIQUIDITY-MINING-RECEIPT-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn liquidity_rebate_id(request: &PublishLiquidityRebateRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-LIQUIDITY-REBATE-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(domain, payload)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    let leaves = records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            Value::String(root_from_record(
                domain,
                &json!({
                    "index": index,
                    "record": record,
                }),
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-LIQUIDITY-MINING-STATE-ROOT",
        record,
    )
}

fn payload_id(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_LIQUIDITY_MINING_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn record_root<I>(domain: &str, records: I) -> String
where
    I: Iterator<Item = Value>,
{
    public_record_root(domain, &records.collect::<Vec<_>>())
}

fn id_list_root<'a, I>(domain: &str, ids: I) -> String
where
    I: Iterator<Item = &'a String>,
{
    let leaves = ids
        .enumerate()
        .map(|(index, id)| {
            Value::String(domain_hash(
                domain,
                &[HashPart::Int(index as i128), HashPart::Str(id)],
                32,
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn require_nonempty(
    field: &str,
    value: &str,
) -> PrivateL2ConfidentialLiquidityMiningRuntimeResult<()> {
    if value.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    Ok(())
}

fn require_unique(
    field: &str,
    values: &[String],
) -> PrivateL2ConfidentialLiquidityMiningRuntimeResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if value.is_empty() {
            return Err(format!("{field} cannot contain empty ids"));
        }
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicate id {value}"));
        }
    }
    Ok(())
}
