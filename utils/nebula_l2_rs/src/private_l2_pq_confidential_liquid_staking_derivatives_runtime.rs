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
    "nebula-private-l2-pq-confidential-liquid-staking-derivatives-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_PROTOCOL_VERSION: &str =
    PROTOCOL_VERSION;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_NOTE_SCHEME: &str =
    "ml-kem-1024+zk-pq-confidential-stake-note-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256s-validator-attestation-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_SHARE_SCHEME: &str =
    "zk-pq-confidential-liquid-staking-share-class-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_REWARD_SCHEME: &str =
    "roots-only-private-reward-snapshot-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_INSURANCE_SCHEME: &str =
    "zk-private-slash-insurance-pool-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_UNSTAKE_SCHEME: &str =
    "pq-confidential-fast-unstake-queue-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_REBATE_SCHEME: &str =
    "roots-only-private-low-fee-lsd-rebate-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_FENCE_SCHEME: &str =
    "deterministic-private-nullifier-fence-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_EVIDENCE_SCHEME: &str =
    "pq-confidential-validator-slashing-evidence-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MONERO_NETWORK:
    &str = "monero-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_LOW_FEE_LANE: &str =
    "devnet-private-l2-pq-lsd-low-fee";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_FAST_LANE: &str =
    "devnet-private-l2-pq-lsd-fast-lane";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEVNET_HEIGHT: u64 =
    1_212_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_EPOCH_BLOCKS: u64 =
    720;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_ATTESTATION_TTL_BLOCKS:
    u64 = 18;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_NOTE_TTL_BLOCKS:
    u64 = 2_880;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_UNSTAKE_TTL_BLOCKS:
    u64 = 21_600;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_REBATE_EPOCH_BLOCKS:
    u64 = 1_440;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_VAULTS: usize =
    262_144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_NOTES: usize =
    2_097_152;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_ATTESTATIONS:
    usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_SHARE_CLASSES:
    usize = 524_288;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_REWARD_SNAPSHOTS:
    usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_INSURANCE_POOLS:
    usize = 262_144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_UNSTAKE_REQUESTS:
    usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_REBATES: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_FENCES: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_EVIDENCE:
    usize = 524_288;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE:
    u64 = 512;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE:
    u64 = 8_192;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_USER_FEE_BPS:
    u64 = 12;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_KEEPER_FEE_BPS:
    u64 = 20;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MIN_REBATE_BPS:
    u64 = 4;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_REBATE_BPS:
    u64 = 24;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MIN_INSURANCE_BPS:
    u64 = 150;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_INSURANCE_BPS:
    u64 = 4_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_FAST_LANE_BUDGET_MICRO_UNITS:
    u64 = 1_000_000_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StakingAsset {
    Xmr,
    Pxmr,
    Dxmr,
    SyntheticValidatorCredit,
    BridgeReserveReceipt,
}

impl StakingAsset {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Xmr => "xmr",
            Self::Pxmr => "pxmr",
            Self::Dxmr => "dxmr",
            Self::SyntheticValidatorCredit => "synthetic_validator_credit",
            Self::BridgeReserveReceipt => "bridge_reserve_receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Bootstrapping,
    Active,
    Rebalancing,
    RewardOnly,
    WithdrawOnly,
    Frozen,
    Retired,
}

impl VaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrapping => "bootstrapping",
            Self::Active => "active",
            Self::Rebalancing => "rebalancing",
            Self::RewardOnly => "reward_only",
            Self::WithdrawOnly => "withdraw_only",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_stakes(self) -> bool {
        matches!(self, Self::Bootstrapping | Self::Active | Self::Rebalancing)
    }

    pub fn accepts_unstakes(self) -> bool {
        !matches!(self, Self::Frozen | Self::Retired)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteStatus {
    Pending,
    Bonded,
    ShareMinted,
    QueuedUnstake,
    Redeemed,
    Slashed,
    Expired,
}

impl NoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Bonded => "bonded",
            Self::ShareMinted => "share_minted",
            Self::QueuedUnstake => "queued_unstake",
            Self::Redeemed => "redeemed",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorAttestationStatus {
    Submitted,
    Accepted,
    Superseded,
    Disputed,
    Expired,
    Slashed,
}

impl ValidatorAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareClassKind {
    Principal,
    Reward,
    SeniorYield,
    JuniorYield,
    SlashProtected,
    FastExit,
}

impl ShareClassKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Principal => "principal",
            Self::Reward => "reward",
            Self::SeniorYield => "senior_yield",
            Self::JuniorYield => "junior_yield",
            Self::SlashProtected => "slash_protected",
            Self::FastExit => "fast_exit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnstakeStatus {
    Queued,
    MatchedFastExit,
    Proving,
    Claimable,
    Claimed,
    Cancelled,
    Slashed,
}

impl UnstakeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::MatchedFastExit => "matched_fast_exit",
            Self::Proving => "proving",
            Self::Claimable => "claimable",
            Self::Claimed => "claimed",
            Self::Cancelled => "cancelled",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    DoubleSign,
    InvalidStateTransition,
    WithheldReward,
    Downtime,
    BadAttestation,
    InsuranceFraud,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DoubleSign => "double_sign",
            Self::InvalidStateTransition => "invalid_state_transition",
            Self::WithheldReward => "withheld_reward",
            Self::Downtime => "downtime",
            Self::BadAttestation => "bad_attestation",
            Self::InsuranceFraud => "insurance_fraud",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub monero_network: String,
    pub low_fee_lane: String,
    pub fast_lane: String,
    pub epoch_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub note_ttl_blocks: u64,
    pub unstake_ttl_blocks: u64,
    pub rebate_epoch_blocks: u64,
    pub max_vaults: usize,
    pub max_notes: usize,
    pub max_attestations: usize,
    pub max_share_classes: usize,
    pub max_reward_snapshots: usize,
    pub max_insurance_pools: usize,
    pub max_unstake_requests: usize,
    pub max_rebates: usize,
    pub max_fences: usize,
    pub max_evidence: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_keeper_fee_bps: u64,
    pub min_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub min_insurance_bps: u64,
    pub max_insurance_bps: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            monero_network: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MONERO_NETWORK.to_string(),
            low_fee_lane: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_LOW_FEE_LANE.to_string(),
            fast_lane: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_FAST_LANE.to_string(),
            epoch_blocks: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_EPOCH_BLOCKS,
            attestation_ttl_blocks: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_ATTESTATION_TTL_BLOCKS,
            note_ttl_blocks: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_NOTE_TTL_BLOCKS,
            unstake_ttl_blocks: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_UNSTAKE_TTL_BLOCKS,
            rebate_epoch_blocks: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_REBATE_EPOCH_BLOCKS,
            max_vaults: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_VAULTS,
            max_notes: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_NOTES,
            max_attestations: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_share_classes: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_SHARE_CLASSES,
            max_reward_snapshots: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_REWARD_SNAPSHOTS,
            max_insurance_pools: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_INSURANCE_POOLS,
            max_unstake_requests: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_UNSTAKE_REQUESTS,
            max_rebates: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_REBATES,
            max_fences: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_FENCES,
            max_evidence: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_EVIDENCE,
            min_privacy_set_size: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_keeper_fee_bps: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_KEEPER_FEE_BPS,
            min_rebate_bps: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MIN_REBATE_BPS,
            max_rebate_bps: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_REBATE_BPS,
            min_insurance_bps: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MIN_INSURANCE_BPS,
            max_insurance_bps: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_MAX_INSURANCE_BPS,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "monero_network": self.monero_network,
            "low_fee_lane": self.low_fee_lane,
            "fast_lane": self.fast_lane,
            "epoch_blocks": self.epoch_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "note_ttl_blocks": self.note_ttl_blocks,
            "unstake_ttl_blocks": self.unstake_ttl_blocks,
            "rebate_epoch_blocks": self.rebate_epoch_blocks,
            "max_vaults": self.max_vaults,
            "max_notes": self.max_notes,
            "max_attestations": self.max_attestations,
            "max_share_classes": self.max_share_classes,
            "max_reward_snapshots": self.max_reward_snapshots,
            "max_insurance_pools": self.max_insurance_pools,
            "max_unstake_requests": self.max_unstake_requests,
            "max_rebates": self.max_rebates,
            "max_fences": self.max_fences,
            "max_evidence": self.max_evidence,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_keeper_fee_bps": self.max_keeper_fee_bps,
            "min_rebate_bps": self.min_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "min_insurance_bps": self.min_insurance_bps,
            "max_insurance_bps": self.max_insurance_bps
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub vaults: u64,
    pub notes: u64,
    pub attestations: u64,
    pub share_classes: u64,
    pub reward_snapshots: u64,
    pub insurance_pools: u64,
    pub unstake_requests: u64,
    pub rebates: u64,
    pub fences: u64,
    pub evidence: u64,
    pub consumed_nullifiers: u64,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "vaults": self.vaults,
            "notes": self.notes,
            "attestations": self.attestations,
            "share_classes": self.share_classes,
            "reward_snapshots": self.reward_snapshots,
            "insurance_pools": self.insurance_pools,
            "unstake_requests": self.unstake_requests,
            "rebates": self.rebates,
            "fences": self.fences,
            "evidence": self.evidence,
            "consumed_nullifiers": self.consumed_nullifiers,
            "public_records": self.public_records
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub vault_root: String,
    pub note_root: String,
    pub attestation_root: String,
    pub share_class_root: String,
    pub reward_snapshot_root: String,
    pub insurance_pool_root: String,
    pub unstake_queue_root: String,
    pub rebate_root: String,
    pub privacy_fence_root: String,
    pub slashing_evidence_root: String,
    pub consumed_nullifier_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counter_root": self.counter_root,
            "vault_root": self.vault_root,
            "note_root": self.note_root,
            "attestation_root": self.attestation_root,
            "share_class_root": self.share_class_root,
            "reward_snapshot_root": self.reward_snapshot_root,
            "insurance_pool_root": self.insurance_pool_root,
            "unstake_queue_root": self.unstake_queue_root,
            "rebate_root": self.rebate_root,
            "privacy_fence_root": self.privacy_fence_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StakingVaultRequest {
    pub operator_commitment: String,
    pub validator_set_root: String,
    pub asset: StakingAsset,
    pub min_stake_micro_units: u64,
    pub max_stake_micro_units: u64,
    pub target_reserve_bps: u64,
    pub user_fee_bps: u64,
    pub keeper_fee_bps: u64,
    pub insurance_bps: u64,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
}

impl StakingVaultRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "operator_commitment": self.operator_commitment,
            "validator_set_root": self.validator_set_root,
            "asset": self.asset.as_str(),
            "min_stake_micro_units": self.min_stake_micro_units,
            "max_stake_micro_units": self.max_stake_micro_units,
            "target_reserve_bps": self.target_reserve_bps,
            "user_fee_bps": self.user_fee_bps,
            "keeper_fee_bps": self.keeper_fee_bps,
            "insurance_bps": self.insurance_bps,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StakingVault {
    pub vault_id: String,
    pub request: StakingVaultRequest,
    pub status: VaultStatus,
    pub created_height: u64,
    pub updated_height: u64,
    pub total_staked_commitment_root: String,
    pub total_share_commitment_root: String,
    pub reward_accumulator_root: String,
    pub reserve_commitment_root: String,
    pub active_share_class_ids: Vec<String>,
    pub last_attestation_id: Option<String>,
}

impl StakingVault {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "updated_height": self.updated_height,
            "total_staked_commitment_root": self.total_staked_commitment_root,
            "total_share_commitment_root": self.total_share_commitment_root,
            "reward_accumulator_root": self.reward_accumulator_root,
            "reserve_commitment_root": self.reserve_commitment_root,
            "active_share_class_ids": self.active_share_class_ids,
            "last_attestation_id": self.last_attestation_id
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedStakeNoteRequest {
    pub vault_id: String,
    pub owner_view_tag_root: String,
    pub stake_ciphertext_root: String,
    pub stake_amount_commitment: String,
    pub entry_exchange_rate_root: String,
    pub note_nullifier: String,
    pub refund_address_commitment: String,
    pub pq_envelope_root: String,
    pub privacy_set_size: u64,
}

impl EncryptedStakeNoteRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "owner_view_tag_root": self.owner_view_tag_root,
            "stake_ciphertext_root": self.stake_ciphertext_root,
            "stake_amount_commitment": self.stake_amount_commitment,
            "entry_exchange_rate_root": self.entry_exchange_rate_root,
            "note_nullifier_root": nullifier_commitment(&self.note_nullifier),
            "refund_address_commitment": self.refund_address_commitment,
            "pq_envelope_root": self.pq_envelope_root,
            "privacy_set_size": self.privacy_set_size
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedStakeNote {
    pub note_id: String,
    pub request: EncryptedStakeNoteRequest,
    pub status: NoteStatus,
    pub opened_height: u64,
    pub expires_height: u64,
    pub share_class_id: Option<String>,
    pub minted_share_commitment_root: Option<String>,
    pub last_reward_snapshot_id: Option<String>,
}

impl EncryptedStakeNote {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "share_class_id": self.share_class_id,
            "minted_share_commitment_root": self.minted_share_commitment_root,
            "last_reward_snapshot_id": self.last_reward_snapshot_id
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqValidatorAttestationRequest {
    pub vault_id: String,
    pub validator_commitment: String,
    pub validator_set_root: String,
    pub bonded_stake_root: String,
    pub reward_rate_root: String,
    pub slash_risk_bps: u64,
    pub liveness_score_bps: u64,
    pub attestation_height: u64,
    pub pq_signature_root: String,
    pub recursive_proof_root: String,
}

impl PqValidatorAttestationRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "validator_commitment": self.validator_commitment,
            "validator_set_root": self.validator_set_root,
            "bonded_stake_root": self.bonded_stake_root,
            "reward_rate_root": self.reward_rate_root,
            "slash_risk_bps": self.slash_risk_bps,
            "liveness_score_bps": self.liveness_score_bps,
            "attestation_height": self.attestation_height,
            "pq_signature_root": self.pq_signature_root,
            "recursive_proof_root": self.recursive_proof_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqValidatorAttestation {
    pub attestation_id: String,
    pub request: PqValidatorAttestationRequest,
    pub status: ValidatorAttestationStatus,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub supersedes: Option<String>,
}

impl PqValidatorAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "supersedes": self.supersedes
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DerivativeShareClassRequest {
    pub vault_id: String,
    pub class_kind: ShareClassKind,
    pub tranche_weight_bps: u64,
    pub fee_priority_bps: u64,
    pub slash_absorption_bps: u64,
    pub share_supply_commitment_root: String,
    pub exchange_rate_root: String,
    pub metadata_root: String,
}

impl DerivativeShareClassRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "class_kind": self.class_kind.as_str(),
            "tranche_weight_bps": self.tranche_weight_bps,
            "fee_priority_bps": self.fee_priority_bps,
            "slash_absorption_bps": self.slash_absorption_bps,
            "share_supply_commitment_root": self.share_supply_commitment_root,
            "exchange_rate_root": self.exchange_rate_root,
            "metadata_root": self.metadata_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DerivativeShareClass {
    pub share_class_id: String,
    pub request: DerivativeShareClassRequest,
    pub created_height: u64,
    pub active: bool,
    pub cumulative_reward_root: String,
    pub cumulative_slash_root: String,
}

impl DerivativeShareClass {
    pub fn public_record(&self) -> Value {
        json!({
            "share_class_id": self.share_class_id,
            "request": self.request.public_record(),
            "created_height": self.created_height,
            "active": self.active,
            "cumulative_reward_root": self.cumulative_reward_root,
            "cumulative_slash_root": self.cumulative_slash_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RewardSnapshot {
    pub snapshot_id: String,
    pub vault_id: String,
    pub epoch: u64,
    pub reward_commitment_root: String,
    pub exchange_rate_root: String,
    pub validator_set_root: String,
    pub distribution_proof_root: String,
    pub posted_height: u64,
    pub privacy_set_size: u64,
}

impl RewardSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "vault_id": self.vault_id,
            "epoch": self.epoch,
            "reward_commitment_root": self.reward_commitment_root,
            "exchange_rate_root": self.exchange_rate_root,
            "validator_set_root": self.validator_set_root,
            "distribution_proof_root": self.distribution_proof_root,
            "posted_height": self.posted_height,
            "privacy_set_size": self.privacy_set_size
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashInsurancePool {
    pub pool_id: String,
    pub vault_id: String,
    pub provider_commitment: String,
    pub coverage_commitment_root: String,
    pub premium_bps: u64,
    pub deductible_bps: u64,
    pub expires_height: u64,
    pub active: bool,
}

impl SlashInsurancePool {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "vault_id": self.vault_id,
            "provider_commitment": self.provider_commitment,
            "coverage_commitment_root": self.coverage_commitment_root,
            "premium_bps": self.premium_bps,
            "deductible_bps": self.deductible_bps,
            "expires_height": self.expires_height,
            "active": self.active
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UnstakeQueueRequest {
    pub note_id: String,
    pub vault_id: String,
    pub share_class_id: String,
    pub burn_share_commitment_root: String,
    pub claim_ciphertext_root: String,
    pub exit_nullifier: String,
    pub max_user_fee_bps: u64,
    pub fast_exit: bool,
    pub privacy_set_size: u64,
}

impl UnstakeQueueRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "vault_id": self.vault_id,
            "share_class_id": self.share_class_id,
            "burn_share_commitment_root": self.burn_share_commitment_root,
            "claim_ciphertext_root": self.claim_ciphertext_root,
            "exit_nullifier_root": nullifier_commitment(&self.exit_nullifier),
            "max_user_fee_bps": self.max_user_fee_bps,
            "fast_exit": self.fast_exit,
            "privacy_set_size": self.privacy_set_size
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UnstakeQueueRecord {
    pub request_id: String,
    pub request: UnstakeQueueRequest,
    pub status: UnstakeStatus,
    pub queued_height: u64,
    pub claimable_height: u64,
    pub matched_liquidity_root: Option<String>,
}

impl UnstakeQueueRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "queued_height": self.queued_height,
            "claimable_height": self.claimable_height,
            "matched_liquidity_root": self.matched_liquidity_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebateRecord {
    pub rebate_id: String,
    pub vault_id: String,
    pub note_or_request_id: String,
    pub payer_commitment: String,
    pub rebate_bps: u64,
    pub fee_paid_micro_units: u64,
    pub rebate_commitment_root: String,
    pub epoch: u64,
    pub posted_height: u64,
}

impl FeeRebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "vault_id": self.vault_id,
            "note_or_request_id": self.note_or_request_id,
            "payer_commitment": self.payer_commitment,
            "rebate_bps": self.rebate_bps,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "rebate_commitment_root": self.rebate_commitment_root,
            "epoch": self.epoch,
            "posted_height": self.posted_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyNullifierFence {
    pub fence_id: String,
    pub scope: String,
    pub subject_id: String,
    pub nullifier_root: String,
    pub anchor_root: String,
    pub opened_height: u64,
    pub expires_height: u64,
    pub privacy_set_size: u64,
}

impl PrivacyNullifierFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "scope": self.scope,
            "subject_id": self.subject_id,
            "nullifier_root": self.nullifier_root,
            "anchor_root": self.anchor_root,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "privacy_set_size": self.privacy_set_size
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidenceRecord {
    pub evidence_id: String,
    pub vault_id: String,
    pub attestation_id: Option<String>,
    pub kind: EvidenceKind,
    pub validator_commitment: String,
    pub evidence_root: String,
    pub slash_bps: u64,
    pub insurance_pool_id: Option<String>,
    pub reporter_commitment: String,
    pub submitted_height: u64,
    pub accepted: bool,
}

impl SlashingEvidenceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "vault_id": self.vault_id,
            "attestation_id": self.attestation_id,
            "kind": self.kind.as_str(),
            "validator_commitment": self.validator_commitment,
            "evidence_root": self.evidence_root,
            "slash_bps": self.slash_bps,
            "insurance_pool_id": self.insurance_pool_id,
            "reporter_commitment": self.reporter_commitment,
            "submitted_height": self.submitted_height,
            "accepted": self.accepted
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub runtime_root: String,
    pub fast_lane_budget_remaining_micro_units: u64,
    pub vaults: BTreeMap<String, StakingVault>,
    pub notes: BTreeMap<String, EncryptedStakeNote>,
    pub attestations: BTreeMap<String, PqValidatorAttestation>,
    pub share_classes: BTreeMap<String, DerivativeShareClass>,
    pub reward_snapshots: BTreeMap<String, RewardSnapshot>,
    pub insurance_pools: BTreeMap<String, SlashInsurancePool>,
    pub unstake_queue: BTreeMap<String, UnstakeQueueRecord>,
    pub rebates: BTreeMap<String, FeeRebateRecord>,
    pub privacy_fences: BTreeMap<String, PrivacyNullifierFence>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidenceRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            counters: Counters::default(),
            current_height: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEVNET_HEIGHT,
            runtime_root: commitment_root("runtime", "private-l2-pq-confidential-lsd-devnet"),
            fast_lane_budget_remaining_micro_units: PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_DEFAULT_FAST_LANE_BUDGET_MICRO_UNITS,
            vaults: BTreeMap::new(),
            notes: BTreeMap::new(),
            attestations: BTreeMap::new(),
            share_classes: BTreeMap::new(),
            reward_snapshots: BTreeMap::new(),
            insurance_pools: BTreeMap::new(),
            unstake_queue: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        }
    }
}

impl State {
    pub fn devnet() -> Result<Self> {
        let mut state = Self::default();
        let vault_id = state.register_vault(StakingVaultRequest {
            operator_commitment: commitment_root("operator", "devnet-lsd-operator"),
            validator_set_root: commitment_root("validator-set", "devnet-monero-pq-validators"),
            asset: StakingAsset::Xmr,
            min_stake_micro_units: 10_000_000,
            max_stake_micro_units: 25_000_000_000_000,
            target_reserve_bps: 700,
            user_fee_bps: 8,
            keeper_fee_bps: 12,
            insurance_bps: 250,
            pq_security_bits: 256,
            privacy_set_size: state.config.batch_privacy_set_size,
        })?;
        let senior = state.create_share_class(DerivativeShareClassRequest {
            vault_id: vault_id.clone(),
            class_kind: ShareClassKind::SlashProtected,
            tranche_weight_bps: 6_500,
            fee_priority_bps: 2_000,
            slash_absorption_bps: 500,
            share_supply_commitment_root: commitment_root("share-supply", "devnet-senior"),
            exchange_rate_root: commitment_root("exchange-rate", "devnet-senior"),
            metadata_root: commitment_root("metadata", "devnet-senior-share"),
        })?;
        let junior = state.create_share_class(DerivativeShareClassRequest {
            vault_id: vault_id.clone(),
            class_kind: ShareClassKind::JuniorYield,
            tranche_weight_bps: 3_500,
            fee_priority_bps: 500,
            slash_absorption_bps: 2_000,
            share_supply_commitment_root: commitment_root("share-supply", "devnet-junior"),
            exchange_rate_root: commitment_root("exchange-rate", "devnet-junior"),
            metadata_root: commitment_root("metadata", "devnet-junior-share"),
        })?;
        state.submit_validator_attestation(PqValidatorAttestationRequest {
            vault_id: vault_id.clone(),
            validator_commitment: commitment_root("validator", "devnet-validator-alpha"),
            validator_set_root: commitment_root("validator-set", "devnet-monero-pq-validators"),
            bonded_stake_root: commitment_root("bonded-stake", "devnet-validator-alpha"),
            reward_rate_root: commitment_root("reward-rate", "devnet-epoch"),
            slash_risk_bps: 25,
            liveness_score_bps: 9_980,
            attestation_height: state.current_height,
            pq_signature_root: commitment_root("pq-signature", "devnet-validator-alpha"),
            recursive_proof_root: commitment_root("recursive-proof", "devnet-validator-alpha"),
        })?;
        state.open_stake_note(EncryptedStakeNoteRequest {
            vault_id: vault_id.clone(),
            owner_view_tag_root: commitment_root("view-tag", "devnet-user"),
            stake_ciphertext_root: commitment_root("stake-ciphertext", "devnet-user"),
            stake_amount_commitment: commitment_root("stake-amount", "devnet-user"),
            entry_exchange_rate_root: commitment_root("entry-rate", "devnet-user"),
            note_nullifier: "devnet-note-nullifier-alpha".to_string(),
            refund_address_commitment: commitment_root("refund", "devnet-user"),
            pq_envelope_root: commitment_root("pq-envelope", "devnet-user"),
            privacy_set_size: state.config.batch_privacy_set_size,
        })?;
        state.register_insurance_pool(
            &vault_id,
            commitment_root("insurance-provider", "devnet-provider"),
            commitment_root("coverage", "devnet-coverage"),
            180,
            250,
            state.current_height + state.config.unstake_ttl_blocks,
        )?;
        state.post_reward_snapshot(
            &vault_id,
            0,
            commitment_root("reward", "devnet-epoch-0"),
            commitment_root("exchange-rate", "devnet-epoch-0"),
            commitment_root("validator-set", "devnet-monero-pq-validators"),
            commitment_root("distribution-proof", "devnet-epoch-0"),
            state.config.batch_privacy_set_size,
        )?;
        state.publish_public_record("devnet_share_pair", &vault_id, json!([senior, junior]));
        Ok(state)
    }

    pub fn register_vault(&mut self, request: StakingVaultRequest) -> Result<String> {
        self.ensure_capacity(self.vaults.len(), self.config.max_vaults, "vault")?;
        self.ensure_privacy_set(request.privacy_set_size, "vault privacy set")?;
        ensure_bps(request.target_reserve_bps, "target reserve")?;
        ensure_bps(request.user_fee_bps, "user fee")?;
        ensure_bps(request.keeper_fee_bps, "keeper fee")?;
        ensure_bps(request.insurance_bps, "insurance")?;
        require_root("operator commitment", &request.operator_commitment)?;
        require_root("validator set root", &request.validator_set_root)?;
        if request.user_fee_bps > self.config.max_user_fee_bps {
            return Err("user fee exceeds configured low fee ceiling".to_string());
        }
        if request.keeper_fee_bps > self.config.max_keeper_fee_bps {
            return Err("keeper fee exceeds configured low fee ceiling".to_string());
        }
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("pq security below configured floor".to_string());
        }
        if request.min_stake_micro_units > request.max_stake_micro_units {
            return Err("min stake exceeds max stake".to_string());
        }
        let nonce = self.counters.vaults.saturating_add(1);
        let vault_id = deterministic_id("vault", nonce, &[request.asset.as_str()]);
        let vault = StakingVault {
            vault_id: vault_id.clone(),
            request,
            status: VaultStatus::Bootstrapping,
            created_height: self.current_height,
            updated_height: self.current_height,
            total_staked_commitment_root: commitment_root("total-staked", &vault_id),
            total_share_commitment_root: commitment_root("total-share", &vault_id),
            reward_accumulator_root: commitment_root("reward-accumulator", &vault_id),
            reserve_commitment_root: commitment_root("reserve", &vault_id),
            active_share_class_ids: Vec::new(),
            last_attestation_id: None,
        };
        self.vaults.insert(vault_id.clone(), vault.clone());
        self.counters.vaults = nonce;
        self.publish_public_record("staking_vault_registered", &vault_id, vault.public_record());
        Ok(vault_id)
    }

    pub fn set_vault_status(&mut self, vault_id: &str, status: VaultStatus) -> Result<()> {
        let record = {
            let vault = self.vaults.get_mut(vault_id).ok_or("unknown vault")?;
            vault.status = status;
            vault.updated_height = self.current_height;
            vault.public_record()
        };
        self.publish_public_record("staking_vault_status", vault_id, record);
        Ok(())
    }

    pub fn open_stake_note(&mut self, request: EncryptedStakeNoteRequest) -> Result<String> {
        self.ensure_capacity(self.notes.len(), self.config.max_notes, "stake note")?;
        self.ensure_privacy_set(request.privacy_set_size, "stake note privacy set")?;
        require_root("stake ciphertext root", &request.stake_ciphertext_root)?;
        require_root("stake amount commitment", &request.stake_amount_commitment)?;
        require_root("pq envelope root", &request.pq_envelope_root)?;
        if !self
            .vaults
            .get(&request.vault_id)
            .ok_or("unknown vault")?
            .status
            .accepts_stakes()
        {
            return Err("vault does not accept stakes".to_string());
        }
        self.consume_nullifier(&request.note_nullifier)?;
        let nonce = self.counters.notes.saturating_add(1);
        let note_id = deterministic_id("stake-note", nonce, &[&request.vault_id]);
        let note = EncryptedStakeNote {
            note_id: note_id.clone(),
            request,
            status: NoteStatus::Pending,
            opened_height: self.current_height,
            expires_height: self.current_height + self.config.note_ttl_blocks,
            share_class_id: None,
            minted_share_commitment_root: None,
            last_reward_snapshot_id: None,
        };
        self.notes.insert(note_id.clone(), note.clone());
        self.counters.notes = nonce;
        self.publish_public_record(
            "encrypted_stake_note_opened",
            &note_id,
            note.public_record(),
        );
        Ok(note_id)
    }

    pub fn mint_derivative_shares(
        &mut self,
        note_id: &str,
        share_class_id: &str,
        minted_share_commitment_root: String,
    ) -> Result<()> {
        require_root(
            "minted share commitment root",
            &minted_share_commitment_root,
        )?;
        let class = self
            .share_classes
            .get(share_class_id)
            .ok_or("unknown share class")?;
        if !class.active {
            return Err("share class is inactive".to_string());
        }
        let record = {
            let note = self.notes.get_mut(note_id).ok_or("unknown stake note")?;
            if note.request.vault_id != class.request.vault_id {
                return Err("share class vault mismatch".to_string());
            }
            if !matches!(note.status, NoteStatus::Pending | NoteStatus::Bonded) {
                return Err("note cannot mint derivative shares".to_string());
            }
            note.status = NoteStatus::ShareMinted;
            note.share_class_id = Some(share_class_id.to_string());
            note.minted_share_commitment_root = Some(minted_share_commitment_root);
            note.public_record()
        };
        self.publish_public_record("derivative_shares_minted", note_id, record);
        Ok(())
    }

    pub fn submit_validator_attestation(
        &mut self,
        request: PqValidatorAttestationRequest,
    ) -> Result<String> {
        self.ensure_capacity(
            self.attestations.len(),
            self.config.max_attestations,
            "validator attestation",
        )?;
        ensure_bps(request.slash_risk_bps, "slash risk")?;
        ensure_bps(request.liveness_score_bps, "liveness score")?;
        require_root("pq signature root", &request.pq_signature_root)?;
        require_root("recursive proof root", &request.recursive_proof_root)?;
        let supersedes = self
            .vaults
            .get(&request.vault_id)
            .ok_or("unknown vault")?
            .last_attestation_id
            .clone();
        let nonce = self.counters.attestations.saturating_add(1);
        let attestation_id = deterministic_id("validator-attestation", nonce, &[&request.vault_id]);
        let record = PqValidatorAttestation {
            attestation_id: attestation_id.clone(),
            request,
            status: ValidatorAttestationStatus::Accepted,
            submitted_height: self.current_height,
            expires_height: self.current_height + self.config.attestation_ttl_blocks,
            supersedes,
        };
        if let Some(old_id) = &record.supersedes {
            if let Some(old) = self.attestations.get_mut(old_id) {
                old.status = ValidatorAttestationStatus::Superseded;
            }
        }
        self.vaults
            .get_mut(&record.request.vault_id)
            .ok_or("unknown vault")?
            .last_attestation_id = Some(attestation_id.clone());
        self.attestations
            .insert(attestation_id.clone(), record.clone());
        self.counters.attestations = nonce;
        self.publish_public_record(
            "pq_validator_attestation_accepted",
            &attestation_id,
            record.public_record(),
        );
        Ok(attestation_id)
    }

    pub fn create_share_class(&mut self, request: DerivativeShareClassRequest) -> Result<String> {
        self.ensure_capacity(
            self.share_classes.len(),
            self.config.max_share_classes,
            "share class",
        )?;
        ensure_bps(request.tranche_weight_bps, "tranche weight")?;
        ensure_bps(request.fee_priority_bps, "fee priority")?;
        ensure_bps(request.slash_absorption_bps, "slash absorption")?;
        require_root(
            "share supply commitment root",
            &request.share_supply_commitment_root,
        )?;
        require_root("exchange rate root", &request.exchange_rate_root)?;
        if !self.vaults.contains_key(&request.vault_id) {
            return Err("unknown vault".to_string());
        }
        let nonce = self.counters.share_classes.saturating_add(1);
        let share_class_id = deterministic_id(
            "share-class",
            nonce,
            &[&request.vault_id, request.class_kind.as_str()],
        );
        let class = DerivativeShareClass {
            share_class_id: share_class_id.clone(),
            request,
            created_height: self.current_height,
            active: true,
            cumulative_reward_root: commitment_root("class-reward", &share_class_id),
            cumulative_slash_root: commitment_root("class-slash", &share_class_id),
        };
        self.vaults
            .get_mut(&class.request.vault_id)
            .ok_or("unknown vault")?
            .active_share_class_ids
            .push(share_class_id.clone());
        self.share_classes
            .insert(share_class_id.clone(), class.clone());
        self.counters.share_classes = nonce;
        self.publish_public_record(
            "derivative_share_class_created",
            &share_class_id,
            class.public_record(),
        );
        Ok(share_class_id)
    }

    pub fn post_reward_snapshot(
        &mut self,
        vault_id: &str,
        epoch: u64,
        reward_commitment_root: String,
        exchange_rate_root: String,
        validator_set_root: String,
        distribution_proof_root: String,
        privacy_set_size: u64,
    ) -> Result<String> {
        self.ensure_capacity(
            self.reward_snapshots.len(),
            self.config.max_reward_snapshots,
            "reward snapshot",
        )?;
        self.ensure_privacy_set(privacy_set_size, "reward privacy set")?;
        require_root("reward commitment root", &reward_commitment_root)?;
        require_root("exchange rate root", &exchange_rate_root)?;
        require_root("distribution proof root", &distribution_proof_root)?;
        if !self.vaults.contains_key(vault_id) {
            return Err("unknown vault".to_string());
        }
        let nonce = self.counters.reward_snapshots.saturating_add(1);
        let snapshot_id = deterministic_id("reward-snapshot", nonce, &[vault_id]);
        let snapshot = RewardSnapshot {
            snapshot_id: snapshot_id.clone(),
            vault_id: vault_id.to_string(),
            epoch,
            reward_commitment_root,
            exchange_rate_root,
            validator_set_root,
            distribution_proof_root,
            posted_height: self.current_height,
            privacy_set_size,
        };
        self.reward_snapshots
            .insert(snapshot_id.clone(), snapshot.clone());
        self.counters.reward_snapshots = nonce;
        self.publish_public_record(
            "reward_snapshot_posted",
            &snapshot_id,
            snapshot.public_record(),
        );
        Ok(snapshot_id)
    }

    pub fn register_insurance_pool(
        &mut self,
        vault_id: &str,
        provider_commitment: String,
        coverage_commitment_root: String,
        premium_bps: u64,
        deductible_bps: u64,
        expires_height: u64,
    ) -> Result<String> {
        self.ensure_capacity(
            self.insurance_pools.len(),
            self.config.max_insurance_pools,
            "insurance pool",
        )?;
        ensure_bps(premium_bps, "premium")?;
        ensure_bps(deductible_bps, "deductible")?;
        require_root("provider commitment", &provider_commitment)?;
        require_root("coverage commitment root", &coverage_commitment_root)?;
        if !self.vaults.contains_key(vault_id) {
            return Err("unknown vault".to_string());
        }
        if premium_bps < self.config.min_insurance_bps
            || premium_bps > self.config.max_insurance_bps
        {
            return Err("premium outside configured insurance bounds".to_string());
        }
        let nonce = self.counters.insurance_pools.saturating_add(1);
        let pool_id = deterministic_id("slash-insurance", nonce, &[vault_id]);
        let pool = SlashInsurancePool {
            pool_id: pool_id.clone(),
            vault_id: vault_id.to_string(),
            provider_commitment,
            coverage_commitment_root,
            premium_bps,
            deductible_bps,
            expires_height,
            active: true,
        };
        self.insurance_pools.insert(pool_id.clone(), pool.clone());
        self.counters.insurance_pools = nonce;
        self.publish_public_record(
            "slash_insurance_pool_registered",
            &pool_id,
            pool.public_record(),
        );
        Ok(pool_id)
    }

    pub fn queue_unstake(&mut self, request: UnstakeQueueRequest) -> Result<String> {
        self.ensure_capacity(
            self.unstake_queue.len(),
            self.config.max_unstake_requests,
            "unstake request",
        )?;
        self.ensure_privacy_set(request.privacy_set_size, "unstake privacy set")?;
        ensure_bps(request.max_user_fee_bps, "unstake user fee")?;
        if request.max_user_fee_bps > self.config.max_user_fee_bps {
            return Err("unstake fee exceeds configured low fee ceiling".to_string());
        }
        if !self
            .vaults
            .get(&request.vault_id)
            .ok_or("unknown vault")?
            .status
            .accepts_unstakes()
        {
            return Err("vault does not accept unstakes".to_string());
        }
        let note = self.notes.get(&request.note_id).ok_or("unknown note")?;
        if note.request.vault_id != request.vault_id {
            return Err("note vault mismatch".to_string());
        }
        if !self.share_classes.contains_key(&request.share_class_id) {
            return Err("unknown share class".to_string());
        }
        self.consume_nullifier(&request.exit_nullifier)?;
        let nonce = self.counters.unstake_requests.saturating_add(1);
        let request_id = deterministic_id("unstake-request", nonce, &[&request.vault_id]);
        let queued = UnstakeQueueRecord {
            request_id: request_id.clone(),
            request,
            status: UnstakeStatus::Queued,
            queued_height: self.current_height,
            claimable_height: self.current_height + self.config.unstake_ttl_blocks,
            matched_liquidity_root: None,
        };
        self.notes
            .get_mut(&queued.request.note_id)
            .ok_or("unknown note")?
            .status = NoteStatus::QueuedUnstake;
        self.unstake_queue
            .insert(request_id.clone(), queued.clone());
        self.counters.unstake_requests = nonce;
        self.publish_public_record("unstake_queued", &request_id, queued.public_record());
        Ok(request_id)
    }

    pub fn match_fast_exit(
        &mut self,
        request_id: &str,
        matched_liquidity_root: String,
    ) -> Result<()> {
        require_root("matched liquidity root", &matched_liquidity_root)?;
        let record = {
            let request = self
                .unstake_queue
                .get_mut(request_id)
                .ok_or("unknown unstake request")?;
            if !request.request.fast_exit {
                return Err("request did not opt into fast exit".to_string());
            }
            request.status = UnstakeStatus::MatchedFastExit;
            request.matched_liquidity_root = Some(matched_liquidity_root);
            request.claimable_height = self.current_height;
            request.public_record()
        };
        self.publish_public_record("fast_exit_matched", request_id, record);
        Ok(())
    }

    pub fn post_fee_rebate(
        &mut self,
        vault_id: &str,
        note_or_request_id: &str,
        payer_commitment: String,
        rebate_bps: u64,
        fee_paid_micro_units: u64,
        rebate_commitment_root: String,
    ) -> Result<String> {
        self.ensure_capacity(self.rebates.len(), self.config.max_rebates, "rebate")?;
        ensure_bps(rebate_bps, "rebate")?;
        require_root("payer commitment", &payer_commitment)?;
        require_root("rebate commitment root", &rebate_commitment_root)?;
        if rebate_bps < self.config.min_rebate_bps || rebate_bps > self.config.max_rebate_bps {
            return Err("rebate outside configured bounds".to_string());
        }
        if !self.vaults.contains_key(vault_id) {
            return Err("unknown vault".to_string());
        }
        let nonce = self.counters.rebates.saturating_add(1);
        let rebate_id = deterministic_id("fee-rebate", nonce, &[vault_id, note_or_request_id]);
        let rebate = FeeRebateRecord {
            rebate_id: rebate_id.clone(),
            vault_id: vault_id.to_string(),
            note_or_request_id: note_or_request_id.to_string(),
            payer_commitment,
            rebate_bps,
            fee_paid_micro_units,
            rebate_commitment_root,
            epoch: self.current_height / self.config.rebate_epoch_blocks,
            posted_height: self.current_height,
        };
        self.rebates.insert(rebate_id.clone(), rebate.clone());
        self.counters.rebates = nonce;
        self.publish_public_record("fee_rebate_posted", &rebate_id, rebate.public_record());
        Ok(rebate_id)
    }

    pub fn open_privacy_fence(
        &mut self,
        scope: &str,
        subject_id: &str,
        nullifier: &str,
        anchor_root: String,
        ttl_blocks: u64,
        privacy_set_size: u64,
    ) -> Result<String> {
        self.ensure_capacity(
            self.privacy_fences.len(),
            self.config.max_fences,
            "privacy fence",
        )?;
        self.ensure_privacy_set(privacy_set_size, "fence privacy set")?;
        ensure_non_empty(scope, "scope")?;
        ensure_non_empty(subject_id, "subject id")?;
        require_root("anchor root", &anchor_root)?;
        let nullifier_root = self.consume_and_return_nullifier(nullifier)?;
        let nonce = self.counters.fences.saturating_add(1);
        let fence_id = deterministic_id("privacy-fence", nonce, &[scope, subject_id]);
        let fence = PrivacyNullifierFence {
            fence_id: fence_id.clone(),
            scope: scope.to_string(),
            subject_id: subject_id.to_string(),
            nullifier_root,
            anchor_root,
            opened_height: self.current_height,
            expires_height: self.current_height + ttl_blocks,
            privacy_set_size,
        };
        self.privacy_fences.insert(fence_id.clone(), fence.clone());
        self.counters.fences = nonce;
        self.publish_public_record(
            "privacy_nullifier_fence_opened",
            &fence_id,
            fence.public_record(),
        );
        Ok(fence_id)
    }

    pub fn submit_slashing_evidence(
        &mut self,
        vault_id: &str,
        attestation_id: Option<String>,
        kind: EvidenceKind,
        validator_commitment: String,
        evidence_root: String,
        slash_bps: u64,
        insurance_pool_id: Option<String>,
        reporter_commitment: String,
    ) -> Result<String> {
        self.ensure_capacity(
            self.slashing_evidence.len(),
            self.config.max_evidence,
            "slashing evidence",
        )?;
        ensure_bps(slash_bps, "slash")?;
        require_root("validator commitment", &validator_commitment)?;
        require_root("evidence root", &evidence_root)?;
        require_root("reporter commitment", &reporter_commitment)?;
        if !self.vaults.contains_key(vault_id) {
            return Err("unknown vault".to_string());
        }
        if let Some(id) = &attestation_id {
            if !self.attestations.contains_key(id) {
                return Err("unknown attestation".to_string());
            }
        }
        if let Some(id) = &insurance_pool_id {
            if !self.insurance_pools.contains_key(id) {
                return Err("unknown insurance pool".to_string());
            }
        }
        let nonce = self.counters.evidence.saturating_add(1);
        let evidence_id = deterministic_id("slashing-evidence", nonce, &[vault_id, kind.as_str()]);
        let record = SlashingEvidenceRecord {
            evidence_id: evidence_id.clone(),
            vault_id: vault_id.to_string(),
            attestation_id: attestation_id.clone(),
            kind,
            validator_commitment,
            evidence_root,
            slash_bps,
            insurance_pool_id,
            reporter_commitment,
            submitted_height: self.current_height,
            accepted: true,
        };
        if let Some(id) = attestation_id {
            if let Some(attestation) = self.attestations.get_mut(&id) {
                attestation.status = ValidatorAttestationStatus::Slashed;
            }
        }
        self.slashing_evidence
            .insert(evidence_id.clone(), record.clone());
        self.counters.evidence = nonce;
        self.publish_public_record(
            "slashing_evidence_accepted",
            &evidence_id,
            record.public_record(),
        );
        Ok(evidence_id)
    }

    pub fn bond_stake_note(&mut self, note_id: &str, bonded_stake_root: String) -> Result<()> {
        require_root("bonded stake root", &bonded_stake_root)?;
        let record = {
            let note = self.notes.get_mut(note_id).ok_or("unknown stake note")?;
            if !matches!(note.status, NoteStatus::Pending) {
                return Err("note cannot be bonded from current status".to_string());
            }
            note.status = NoteStatus::Bonded;
            let mut record = note.public_record();
            record["bonded_stake_root"] = json!(bonded_stake_root);
            record
        };
        self.publish_public_record("stake_note_bonded", note_id, record);
        Ok(())
    }

    pub fn apply_reward_snapshot_to_note(
        &mut self,
        note_id: &str,
        snapshot_id: &str,
        note_reward_commitment_root: String,
    ) -> Result<()> {
        require_root("note reward commitment root", &note_reward_commitment_root)?;
        let snapshot = self
            .reward_snapshots
            .get(snapshot_id)
            .ok_or("unknown reward snapshot")?;
        let record = {
            let note = self.notes.get_mut(note_id).ok_or("unknown stake note")?;
            if note.request.vault_id != snapshot.vault_id {
                return Err("snapshot vault mismatch".to_string());
            }
            if !matches!(note.status, NoteStatus::Bonded | NoteStatus::ShareMinted) {
                return Err("note cannot receive reward snapshot".to_string());
            }
            note.last_reward_snapshot_id = Some(snapshot_id.to_string());
            let mut record = note.public_record();
            record["note_reward_commitment_root"] = json!(note_reward_commitment_root);
            record
        };
        self.publish_public_record("reward_snapshot_applied_to_note", note_id, record);
        Ok(())
    }

    pub fn deactivate_share_class(
        &mut self,
        share_class_id: &str,
        final_exchange_rate_root: String,
    ) -> Result<()> {
        require_root("final exchange rate root", &final_exchange_rate_root)?;
        let (vault_id, record) = {
            let class = self
                .share_classes
                .get_mut(share_class_id)
                .ok_or("unknown share class")?;
            class.active = false;
            class.request.exchange_rate_root = final_exchange_rate_root;
            (class.request.vault_id.clone(), class.public_record())
        };
        if let Some(vault) = self.vaults.get_mut(&vault_id) {
            vault
                .active_share_class_ids
                .retain(|active_id| active_id != share_class_id);
            vault.updated_height = self.current_height;
        }
        self.publish_public_record("derivative_share_class_deactivated", share_class_id, record);
        Ok(())
    }

    pub fn update_share_class_roots(
        &mut self,
        share_class_id: &str,
        share_supply_commitment_root: String,
        exchange_rate_root: String,
        cumulative_reward_root: String,
        cumulative_slash_root: String,
    ) -> Result<()> {
        require_root(
            "share supply commitment root",
            &share_supply_commitment_root,
        )?;
        require_root("exchange rate root", &exchange_rate_root)?;
        require_root("cumulative reward root", &cumulative_reward_root)?;
        require_root("cumulative slash root", &cumulative_slash_root)?;
        let record = {
            let class = self
                .share_classes
                .get_mut(share_class_id)
                .ok_or("unknown share class")?;
            if !class.active {
                return Err("share class is inactive".to_string());
            }
            class.request.share_supply_commitment_root = share_supply_commitment_root;
            class.request.exchange_rate_root = exchange_rate_root;
            class.cumulative_reward_root = cumulative_reward_root;
            class.cumulative_slash_root = cumulative_slash_root;
            class.public_record()
        };
        self.publish_public_record(
            "derivative_share_class_roots_updated",
            share_class_id,
            record,
        );
        Ok(())
    }

    pub fn mark_unstake_proving(
        &mut self,
        request_id: &str,
        withdrawal_proof_root: String,
    ) -> Result<()> {
        require_root("withdrawal proof root", &withdrawal_proof_root)?;
        let record = {
            let request = self
                .unstake_queue
                .get_mut(request_id)
                .ok_or("unknown unstake request")?;
            if !matches!(
                request.status,
                UnstakeStatus::Queued | UnstakeStatus::MatchedFastExit
            ) {
                return Err("unstake request cannot enter proving".to_string());
            }
            request.status = UnstakeStatus::Proving;
            let mut record = request.public_record();
            record["withdrawal_proof_root"] = json!(withdrawal_proof_root);
            record
        };
        self.publish_public_record("unstake_proving", request_id, record);
        Ok(())
    }

    pub fn mark_unstake_claimable(
        &mut self,
        request_id: &str,
        claim_anchor_root: String,
    ) -> Result<()> {
        require_root("claim anchor root", &claim_anchor_root)?;
        let record = {
            let request = self
                .unstake_queue
                .get_mut(request_id)
                .ok_or("unknown unstake request")?;
            if !matches!(
                request.status,
                UnstakeStatus::Queued | UnstakeStatus::MatchedFastExit | UnstakeStatus::Proving
            ) {
                return Err("unstake request cannot become claimable".to_string());
            }
            request.status = UnstakeStatus::Claimable;
            request.claimable_height = self.current_height;
            let mut record = request.public_record();
            record["claim_anchor_root"] = json!(claim_anchor_root);
            record
        };
        self.publish_public_record("unstake_claimable", request_id, record);
        Ok(())
    }

    pub fn claim_unstake(
        &mut self,
        request_id: &str,
        payout_commitment_root: String,
    ) -> Result<()> {
        require_root("payout commitment root", &payout_commitment_root)?;
        let (note_id, record) = {
            let request = self
                .unstake_queue
                .get_mut(request_id)
                .ok_or("unknown unstake request")?;
            if !matches!(request.status, UnstakeStatus::Claimable) {
                return Err("unstake request is not claimable".to_string());
            }
            if request.claimable_height > self.current_height {
                return Err("unstake request is still timelocked".to_string());
            }
            request.status = UnstakeStatus::Claimed;
            let mut record = request.public_record();
            record["payout_commitment_root"] = json!(payout_commitment_root);
            (request.request.note_id.clone(), record)
        };
        if let Some(note) = self.notes.get_mut(&note_id) {
            note.status = NoteStatus::Redeemed;
        }
        self.publish_public_record("unstake_claimed", request_id, record);
        Ok(())
    }

    pub fn cancel_unstake(
        &mut self,
        request_id: &str,
        cancellation_proof_root: String,
    ) -> Result<()> {
        require_root("cancellation proof root", &cancellation_proof_root)?;
        let (note_id, record) = {
            let request = self
                .unstake_queue
                .get_mut(request_id)
                .ok_or("unknown unstake request")?;
            if !matches!(
                request.status,
                UnstakeStatus::Queued | UnstakeStatus::MatchedFastExit | UnstakeStatus::Proving
            ) {
                return Err("unstake request cannot be cancelled".to_string());
            }
            request.status = UnstakeStatus::Cancelled;
            let mut record = request.public_record();
            record["cancellation_proof_root"] = json!(cancellation_proof_root);
            (request.request.note_id.clone(), record)
        };
        if let Some(note) = self.notes.get_mut(&note_id) {
            note.status = NoteStatus::ShareMinted;
        }
        self.publish_public_record("unstake_cancelled", request_id, record);
        Ok(())
    }

    pub fn dispute_attestation(
        &mut self,
        attestation_id: &str,
        dispute_root: String,
    ) -> Result<()> {
        require_root("dispute root", &dispute_root)?;
        let record = {
            let attestation = self
                .attestations
                .get_mut(attestation_id)
                .ok_or("unknown attestation")?;
            if !matches!(attestation.status, ValidatorAttestationStatus::Accepted) {
                return Err("attestation cannot be disputed".to_string());
            }
            attestation.status = ValidatorAttestationStatus::Disputed;
            let mut record = attestation.public_record();
            record["dispute_root"] = json!(dispute_root);
            record
        };
        self.publish_public_record("pq_validator_attestation_disputed", attestation_id, record);
        Ok(())
    }

    pub fn reject_attestation(
        &mut self,
        attestation_id: &str,
        rejection_root: String,
    ) -> Result<()> {
        require_root("rejection root", &rejection_root)?;
        let record = {
            let attestation = self
                .attestations
                .get_mut(attestation_id)
                .ok_or("unknown attestation")?;
            if !matches!(
                attestation.status,
                ValidatorAttestationStatus::Submitted
                    | ValidatorAttestationStatus::Accepted
                    | ValidatorAttestationStatus::Disputed
            ) {
                return Err("attestation cannot be rejected".to_string());
            }
            attestation.status = ValidatorAttestationStatus::Expired;
            let mut record = attestation.public_record();
            record["rejection_root"] = json!(rejection_root);
            record
        };
        self.publish_public_record("pq_validator_attestation_rejected", attestation_id, record);
        Ok(())
    }

    pub fn retire_insurance_pool(
        &mut self,
        pool_id: &str,
        final_coverage_root: String,
    ) -> Result<()> {
        require_root("final coverage root", &final_coverage_root)?;
        let record = {
            let pool = self
                .insurance_pools
                .get_mut(pool_id)
                .ok_or("unknown insurance pool")?;
            pool.active = false;
            pool.coverage_commitment_root = final_coverage_root;
            pool.public_record()
        };
        self.publish_public_record("slash_insurance_pool_retired", pool_id, record);
        Ok(())
    }

    pub fn settle_insurance_claim(
        &mut self,
        evidence_id: &str,
        pool_id: &str,
        settlement_root: String,
    ) -> Result<()> {
        require_root("insurance settlement root", &settlement_root)?;
        let evidence = self
            .slashing_evidence
            .get(evidence_id)
            .ok_or("unknown slashing evidence")?;
        let pool = self
            .insurance_pools
            .get(pool_id)
            .ok_or("unknown insurance pool")?;
        if evidence.vault_id != pool.vault_id {
            return Err("insurance pool vault mismatch".to_string());
        }
        let record = json!({
            "evidence_id": evidence_id,
            "pool_id": pool_id,
            "vault_id": evidence.vault_id,
            "settlement_root": settlement_root,
            "settled_height": self.current_height
        });
        self.publish_public_record("slash_insurance_claim_settled", evidence_id, record);
        Ok(())
    }

    pub fn slash_note(
        &mut self,
        note_id: &str,
        evidence_id: &str,
        slash_commitment_root: String,
    ) -> Result<()> {
        require_root("slash commitment root", &slash_commitment_root)?;
        if !self.slashing_evidence.contains_key(evidence_id) {
            return Err("unknown slashing evidence".to_string());
        }
        let record = {
            let note = self.notes.get_mut(note_id).ok_or("unknown stake note")?;
            if matches!(note.status, NoteStatus::Redeemed | NoteStatus::Expired) {
                return Err("note cannot be slashed".to_string());
            }
            note.status = NoteStatus::Slashed;
            let mut record = note.public_record();
            record["evidence_id"] = json!(evidence_id);
            record["slash_commitment_root"] = json!(slash_commitment_root);
            record
        };
        self.publish_public_record("stake_note_slashed", note_id, record);
        Ok(())
    }

    pub fn advance_height(&mut self, blocks: u64) {
        self.current_height = self.current_height.saturating_add(blocks);
    }

    pub fn expire_old_records(&mut self) {
        for note in self.notes.values_mut() {
            if matches!(note.status, NoteStatus::Pending | NoteStatus::Bonded)
                && note.expires_height <= self.current_height
            {
                note.status = NoteStatus::Expired;
            }
        }
        for attestation in self.attestations.values_mut() {
            if matches!(
                attestation.status,
                ValidatorAttestationStatus::Submitted | ValidatorAttestationStatus::Accepted
            ) && attestation.expires_height <= self.current_height
            {
                attestation.status = ValidatorAttestationStatus::Expired;
            }
        }
        for pool in self.insurance_pools.values_mut() {
            if pool.expires_height <= self.current_height {
                pool.active = false;
            }
        }
    }

    pub fn roots(&self) -> Roots {
        let config_root =
            root_from_record("PRIVATE-L2-PQ-LSD-CONFIG", &self.config.public_record());
        let counter_root =
            root_from_record("PRIVATE-L2-PQ-LSD-COUNTERS", &self.counters.public_record());
        let vault_root = public_record_root(
            "PRIVATE-L2-PQ-LSD-VAULTS",
            self.vaults
                .values()
                .map(StakingVault::public_record)
                .collect(),
        );
        let note_root = public_record_root(
            "PRIVATE-L2-PQ-LSD-NOTES",
            self.notes
                .values()
                .map(EncryptedStakeNote::public_record)
                .collect(),
        );
        let attestation_root = public_record_root(
            "PRIVATE-L2-PQ-LSD-ATTESTATIONS",
            self.attestations
                .values()
                .map(PqValidatorAttestation::public_record)
                .collect(),
        );
        let share_class_root = public_record_root(
            "PRIVATE-L2-PQ-LSD-SHARE-CLASSES",
            self.share_classes
                .values()
                .map(DerivativeShareClass::public_record)
                .collect(),
        );
        let reward_snapshot_root = public_record_root(
            "PRIVATE-L2-PQ-LSD-REWARD-SNAPSHOTS",
            self.reward_snapshots
                .values()
                .map(RewardSnapshot::public_record)
                .collect(),
        );
        let insurance_pool_root = public_record_root(
            "PRIVATE-L2-PQ-LSD-INSURANCE-POOLS",
            self.insurance_pools
                .values()
                .map(SlashInsurancePool::public_record)
                .collect(),
        );
        let unstake_queue_root = public_record_root(
            "PRIVATE-L2-PQ-LSD-UNSTAKE-QUEUE",
            self.unstake_queue
                .values()
                .map(UnstakeQueueRecord::public_record)
                .collect(),
        );
        let rebate_root = public_record_root(
            "PRIVATE-L2-PQ-LSD-REBATES",
            self.rebates
                .values()
                .map(FeeRebateRecord::public_record)
                .collect(),
        );
        let privacy_fence_root = public_record_root(
            "PRIVATE-L2-PQ-LSD-PRIVACY-FENCES",
            self.privacy_fences
                .values()
                .map(PrivacyNullifierFence::public_record)
                .collect(),
        );
        let slashing_evidence_root = public_record_root(
            "PRIVATE-L2-PQ-LSD-SLASHING-EVIDENCE",
            self.slashing_evidence
                .values()
                .map(SlashingEvidenceRecord::public_record)
                .collect(),
        );
        let consumed_nullifier_root = public_record_root(
            "PRIVATE-L2-PQ-LSD-CONSUMED-NULLIFIERS",
            self.consumed_nullifiers
                .iter()
                .map(|nullifier| json!({ "nullifier_root": nullifier }))
                .collect(),
        );
        let public_record_root_value = public_record_root(
            "PRIVATE-L2-PQ-LSD-PUBLIC-RECORDS",
            self.public_records.values().cloned().collect(),
        );
        let state_root = state_root_from_record(&json!({
            "config_root": config_root,
            "counter_root": counter_root,
            "vault_root": vault_root,
            "note_root": note_root,
            "attestation_root": attestation_root,
            "share_class_root": share_class_root,
            "reward_snapshot_root": reward_snapshot_root,
            "insurance_pool_root": insurance_pool_root,
            "unstake_queue_root": unstake_queue_root,
            "rebate_root": rebate_root,
            "privacy_fence_root": privacy_fence_root,
            "slashing_evidence_root": slashing_evidence_root,
            "consumed_nullifier_root": consumed_nullifier_root,
            "public_record_root": public_record_root_value,
            "runtime_root": self.runtime_root,
            "current_height": self.current_height,
            "fast_lane_budget_remaining_micro_units": self.fast_lane_budget_remaining_micro_units
        }));
        Roots {
            config_root,
            counter_root,
            vault_root,
            note_root,
            attestation_root,
            share_class_root,
            reward_snapshot_root,
            insurance_pool_root,
            unstake_queue_root,
            rebate_root,
            privacy_fence_root,
            slashing_evidence_root,
            consumed_nullifier_root,
            public_record_root: public_record_root_value,
            state_root,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_pq_confidential_liquid_staking_derivatives_runtime_state",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "hash_suite": PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_HASH_SUITE,
            "note_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_NOTE_SCHEME,
            "attestation_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_ATTESTATION_SCHEME,
            "share_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_SHARE_SCHEME,
            "reward_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_REWARD_SCHEME,
            "insurance_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_INSURANCE_SCHEME,
            "unstake_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_UNSTAKE_SCHEME,
            "rebate_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_REBATE_SCHEME,
            "fence_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_FENCE_SCHEME,
            "evidence_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_EVIDENCE_SCHEME,
            "current_height": self.current_height,
            "runtime_root": self.runtime_root,
            "fast_lane_budget_remaining_micro_units": self.fast_lane_budget_remaining_micro_units,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "counts": {
                "vaults": self.vaults.len(),
                "notes": self.notes.len(),
                "attestations": self.attestations.len(),
                "share_classes": self.share_classes.len(),
                "reward_snapshots": self.reward_snapshots.len(),
                "insurance_pools": self.insurance_pools.len(),
                "unstake_queue": self.unstake_queue.len(),
                "rebates": self.rebates.len(),
                "privacy_fences": self.privacy_fences.len(),
                "slashing_evidence": self.slashing_evidence.len()
            }
        })
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_state_root();
        json!({
            "state_root": state_root_from_record(&record),
            "record": record
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn ensure_capacity(&self, len: usize, limit: usize, label: &str) -> Result<()> {
        if len >= limit {
            return Err(format!("{label} capacity reached"));
        }
        Ok(())
    }

    fn ensure_privacy_set(&self, privacy_set_size: u64, label: &str) -> Result<()> {
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err(format!("{label} below configured privacy minimum"));
        }
        Ok(())
    }

    fn consume_nullifier(&mut self, nullifier: &str) -> Result<()> {
        self.consume_and_return_nullifier(nullifier).map(|_| ())
    }

    fn consume_and_return_nullifier(&mut self, nullifier: &str) -> Result<String> {
        require_root("nullifier", nullifier)?;
        let nullifier_hash = nullifier_commitment(nullifier);
        if !self.consumed_nullifiers.insert(nullifier_hash.clone()) {
            return Err("nullifier already consumed".to_string());
        }
        self.counters.consumed_nullifiers = self.counters.consumed_nullifiers.saturating_add(1);
        Ok(nullifier_hash)
    }

    fn publish_public_record(&mut self, record_kind: &str, subject_id: &str, payload: Value) {
        let record_id = public_record_id(record_kind, subject_id, &payload);
        self.public_records.insert(
            record_id,
            roots_only_public_record(record_kind, subject_id, &payload),
        );
        self.counters.public_records = self.public_records.len() as u64;
    }
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn public_record_root(domain: &str, leaves: Vec<Value>) -> String {
    merkle_root(domain, &leaves)
}

pub fn deterministic_id(kind: &str, nonce: u64, labels: &[&str]) -> String {
    let mut parts = vec![
        HashPart::Str(kind),
        HashPart::Str(CHAIN_ID),
        HashPart::U64(nonce),
    ];
    for label in labels {
        parts.push(HashPart::Str(label));
    }
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-LSD-DETERMINISTIC-ID",
        &parts,
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("PRIVATE-L2-PQ-CONFIDENTIAL-LSD-STATE-ROOT", record)
}

pub fn public_record_id(record_kind: &str, subject_id: &str, payload: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-LSD-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn roots_only_public_record(record_kind: &str, subject_id: &str, payload: &Value) -> Value {
    json!({
        "kind": "roots_only_public_record",
        "record_kind": record_kind,
        "subject_id": subject_id,
        "payload_root": payload_root("PRIVATE-L2-PQ-CONFIDENTIAL-LSD-PAYLOAD-ROOT", payload),
        "record_id": public_record_id(record_kind, subject_id, payload)
    })
}

pub fn roots_only_payload(kind: &str, subject_id: &str, payload: &Value) -> String {
    payload_root(
        "PRIVATE-L2-PQ-CONFIDENTIAL-LSD-ROOTS-ONLY-PAYLOAD",
        &json!({
            "kind": kind,
            "subject_id": subject_id,
            "payload": payload
        }),
    )
}

pub fn commitment_root(domain: &str, label: &str) -> String {
    payload_root(
        "PRIVATE-L2-PQ-CONFIDENTIAL-LSD-COMMITMENT",
        &json!({ "domain": domain, "label": label }),
    )
}

pub fn nullifier_commitment(nullifier: &str) -> String {
    payload_root(
        "PRIVATE-L2-PQ-CONFIDENTIAL-LSD-NULLIFIER",
        &json!({ "nullifier": nullifier }),
    )
}

pub fn ensure_non_empty(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

pub fn require_root(label: &str, root: &str) -> Result<()> {
    ensure_non_empty(root, label)?;
    if root.len() < 16 {
        return Err(format!("{label} must look like a deterministic root"));
    }
    Ok(())
}

pub fn ensure_bps(value: u64, label: &str) -> Result<()> {
    if value > PRIVATE_L2_PQ_CONFIDENTIAL_LIQUID_STAKING_DERIVATIVES_RUNTIME_MAX_BPS {
        return Err(format!("{label} exceeds max bps"));
    }
    Ok(())
}

pub fn devnet() -> Result<State> {
    State::devnet()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}
