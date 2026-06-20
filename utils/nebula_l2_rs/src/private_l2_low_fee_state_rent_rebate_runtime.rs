use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeeStateRentRebateRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-state-rent-rebate-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-state-rent-rebate-v1";
pub const PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_COMPRESSION_SUITE: &str =
    "private-contract-state-delta-compression-v1";
pub const PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_PROOF_SUITE: &str =
    "recursive-state-rent-rebate-proof-v1";
pub const PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEVNET_HEIGHT: u64 = 734_000;
pub const PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_MAX_MARKETS: usize = 524_288;
pub const PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_MAX_COMMITMENTS: usize = 2_097_152;
pub const PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize = 2_097_152;
pub const PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_MAX_CLAIMS: usize = 4_194_304;
pub const PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_MAX_VOUCHERS: usize = 2_097_152;
pub const PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_MAX_BATCHES: usize = 1_048_576;
pub const PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_MAX_RECEIPTS: usize = 4_194_304;
pub const PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_MIN_PRIVACY_SET: usize = 128;
pub const PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_BATCH_PRIVACY_SET: usize = 4_096;
pub const PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_TARGET_MAX_RENT_BPS: u64 = 20;
pub const PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 = 8_500;
pub const PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_SPONSOR_COVER_BPS: u64 = 9_200;
pub const PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_COMPRESSION_REWARD_BPS: u64 = 7_500;
pub const PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_VOUCHER_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_MARKET_EPOCH_BLOCKS: u64 = 720;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RentMarketKind {
    PrivateContractStorage,
    ConfidentialTokenState,
    DefiPoolState,
    PerpMarginState,
    OracleCacheState,
    BridgeExitState,
    AccountSessionState,
    RuntimeCheckpointState,
}

impl RentMarketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateContractStorage => "private_contract_storage",
            Self::ConfidentialTokenState => "confidential_token_state",
            Self::DefiPoolState => "defi_pool_state",
            Self::PerpMarginState => "perp_margin_state",
            Self::OracleCacheState => "oracle_cache_state",
            Self::BridgeExitState => "bridge_exit_state",
            Self::AccountSessionState => "account_session_state",
            Self::RuntimeCheckpointState => "runtime_checkpoint_state",
        }
    }

    pub fn latency_weight(self) -> u64 {
        match self {
            Self::BridgeExitState => 10_000,
            Self::PerpMarginState => 9_600,
            Self::DefiPoolState => 9_300,
            Self::PrivateContractStorage => 8_700,
            Self::ConfidentialTokenState => 8_400,
            Self::OracleCacheState => 8_000,
            Self::AccountSessionState => 7_700,
            Self::RuntimeCheckpointState => 7_100,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RentMarketStatus {
    Proposed,
    Open,
    Congested,
    Discounted,
    Settling,
    Closed,
    Slashed,
}

impl RentMarketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Open => "open",
            Self::Congested => "congested",
            Self::Discounted => "discounted",
            Self::Settling => "settling",
            Self::Closed => "closed",
            Self::Slashed => "slashed",
        }
    }

    pub fn accepts_commitments(self) -> bool {
        matches!(self, Self::Open | Self::Congested | Self::Discounted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionKind {
    SparseMerkleDelta,
    ZstdWitnessBundle,
    PoseidonLeafPack,
    RangeProofFold,
    AccessListPrune,
    ContractSlotSquash,
    EventLogElide,
    RecursiveCheckpoint,
}

impl CompressionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SparseMerkleDelta => "sparse_merkle_delta",
            Self::ZstdWitnessBundle => "zstd_witness_bundle",
            Self::PoseidonLeafPack => "poseidon_leaf_pack",
            Self::RangeProofFold => "range_proof_fold",
            Self::AccessListPrune => "access_list_prune",
            Self::ContractSlotSquash => "contract_slot_squash",
            Self::EventLogElide => "event_log_elide",
            Self::RecursiveCheckpoint => "recursive_checkpoint",
        }
    }

    pub fn expected_rebate_multiplier_bps(self) -> u64 {
        match self {
            Self::RecursiveCheckpoint => 9_800,
            Self::ContractSlotSquash => 9_300,
            Self::SparseMerkleDelta => 8_900,
            Self::AccessListPrune => 8_400,
            Self::PoseidonLeafPack => 8_100,
            Self::RangeProofFold => 7_800,
            Self::EventLogElide => 7_500,
            Self::ZstdWitnessBundle => 7_200,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Submitted,
    Sponsored,
    ProofCached,
    Claimable,
    Batched,
    Settled,
    Rejected,
    Expired,
}

impl CommitmentStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Sponsored | Self::ProofCached | Self::Claimable | Self::Batched
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReservationStatus {
    Reserved,
    PartiallyConsumed,
    Consumed,
    RebateQueued,
    Refunded,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateClaimStatus {
    Submitted,
    ProofLinked,
    VoucherAttached,
    Approved,
    Batched,
    Paid,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofCacheVoucherStatus {
    Open,
    Attached,
    Consumed,
    Rebated,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementBatchStatus {
    Proposed,
    Executing,
    SettlementReady,
    Settled,
    Rebated,
    Disputed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    RentMarketOpened,
    StateCompressed,
    SponsorReserved,
    RebateClaimed,
    ProofVoucherIssued,
    BatchBuilt,
    SettlementPublished,
    RebatePaid,
    MarketSlashed,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RentMarketOpened => "rent_market_opened",
            Self::StateCompressed => "state_compressed",
            Self::SponsorReserved => "sponsor_reserved",
            Self::RebateClaimed => "rebate_claimed",
            Self::ProofVoucherIssued => "proof_voucher_issued",
            Self::BatchBuilt => "batch_built",
            Self::SettlementPublished => "settlement_published",
            Self::RebatePaid => "rebate_paid",
            Self::MarketSlashed => "market_slashed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub compression_suite: String,
    pub proof_suite: String,
    pub max_markets: usize,
    pub max_commitments: usize,
    pub max_reservations: usize,
    pub max_claims: usize,
    pub max_vouchers: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub min_privacy_set_size: usize,
    pub batch_privacy_set_size: usize,
    pub target_max_rent_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub compression_reward_bps: u64,
    pub reservation_ttl_blocks: u64,
    pub voucher_ttl_blocks: u64,
    pub market_epoch_blocks: u64,
    pub devnet_height: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_HASH_SUITE.to_string(),
            pq_auth_suite: PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_PQ_AUTH_SUITE.to_string(),
            compression_suite: PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_COMPRESSION_SUITE
                .to_string(),
            proof_suite: PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_PROOF_SUITE.to_string(),
            max_markets: PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_MAX_MARKETS,
            max_commitments: PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_MAX_COMMITMENTS,
            max_reservations: PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_claims: PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_MAX_CLAIMS,
            max_vouchers: PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_MAX_VOUCHERS,
            max_batches: PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts: PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_MAX_RECEIPTS,
            min_privacy_set_size:
                PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            batch_privacy_set_size:
                PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_BATCH_PRIVACY_SET,
            target_max_rent_bps:
                PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_TARGET_MAX_RENT_BPS,
            target_rebate_bps:
                PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            sponsor_cover_bps:
                PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_SPONSOR_COVER_BPS,
            compression_reward_bps:
                PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_COMPRESSION_REWARD_BPS,
            reservation_ttl_blocks:
                PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            voucher_ttl_blocks:
                PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_VOUCHER_TTL_BLOCKS,
            market_epoch_blocks:
                PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEFAULT_MARKET_EPOCH_BLOCKS,
            devnet_height: PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_DEVNET_HEIGHT,
        }
    }

    pub fn validate(&self) -> PrivateL2LowFeeStateRentRebateRuntimeResult<()> {
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("hash_suite", &self.hash_suite)?;
        require_non_empty("pq_auth_suite", &self.pq_auth_suite)?;
        require_non_empty("compression_suite", &self.compression_suite)?;
        require_non_empty("proof_suite", &self.proof_suite)?;
        require_positive("max_markets", self.max_markets)?;
        require_positive("max_commitments", self.max_commitments)?;
        require_positive("max_reservations", self.max_reservations)?;
        require_positive("max_claims", self.max_claims)?;
        require_positive("max_vouchers", self.max_vouchers)?;
        require_positive("max_batches", self.max_batches)?;
        require_positive("max_receipts", self.max_receipts)?;
        require_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        require_positive("batch_privacy_set_size", self.batch_privacy_set_size)?;
        if self.batch_privacy_set_size < self.min_privacy_set_size {
            return Err("batch_privacy_set_size cannot be below min_privacy_set_size".to_string());
        }
        require_bps("target_max_rent_bps", self.target_max_rent_bps)?;
        require_bps("target_rebate_bps", self.target_rebate_bps)?;
        require_bps("sponsor_cover_bps", self.sponsor_cover_bps)?;
        require_bps("compression_reward_bps", self.compression_reward_bps)?;
        if self.reservation_ttl_blocks == 0 {
            return Err("reservation_ttl_blocks must be positive".to_string());
        }
        if self.voucher_ttl_blocks == 0 {
            return Err("voucher_ttl_blocks must be positive".to_string());
        }
        if self.market_epoch_blocks == 0 {
            return Err("market_epoch_blocks must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub market_counter: u64,
    pub commitment_counter: u64,
    pub reservation_counter: u64,
    pub claim_counter: u64,
    pub voucher_counter: u64,
    pub batch_counter: u64,
    pub receipt_counter: u64,
    pub rebate_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenRentMarketRequest {
    pub market_operator_commitment: String,
    pub market_kind: RentMarketKind,
    pub contract_class_root: String,
    pub state_namespace_root: String,
    pub rent_curve_root: String,
    pub sponsor_pool_root: String,
    pub compression_policy_root: String,
    pub max_rent_bps: u64,
    pub target_rebate_bps: u64,
    pub min_compression_ratio_bps: u64,
    pub opens_at_height: u64,
    pub closes_at_height: u64,
    pub market_nonce: String,
}

impl OpenRentMarketRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeStateRentRebateRuntimeResult<()> {
        require_non_empty(
            "market_operator_commitment",
            &self.market_operator_commitment,
        )?;
        require_root("contract_class_root", &self.contract_class_root)?;
        require_root("state_namespace_root", &self.state_namespace_root)?;
        require_root("rent_curve_root", &self.rent_curve_root)?;
        require_root("sponsor_pool_root", &self.sponsor_pool_root)?;
        require_root("compression_policy_root", &self.compression_policy_root)?;
        require_bps("max_rent_bps", self.max_rent_bps)?;
        require_bps("target_rebate_bps", self.target_rebate_bps)?;
        require_bps("min_compression_ratio_bps", self.min_compression_ratio_bps)?;
        require_non_empty("market_nonce", &self.market_nonce)?;
        if self.max_rent_bps > config.target_max_rent_bps {
            return Err("max_rent_bps exceeds low-fee runtime target".to_string());
        }
        if self.target_rebate_bps < config.target_rebate_bps {
            return Err("target_rebate_bps is below runtime target".to_string());
        }
        if self.opens_at_height >= self.closes_at_height {
            return Err("opens_at_height must be below closes_at_height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitCompressedStateCommitmentRequest {
    pub market_id: String,
    pub contract_commitment: String,
    pub account_commitment: String,
    pub compression_kind: CompressionKind,
    pub state_root_before: String,
    pub compressed_state_root: String,
    pub decompression_hint_root: String,
    pub access_pattern_root: String,
    pub privacy_set_root: String,
    pub rent_nullifier_root: String,
    pub storage_slots_before: u64,
    pub storage_slots_after: u64,
    pub bytes_before: u64,
    pub bytes_after: u64,
    pub max_user_fee_bps: u64,
    pub submitted_at_height: u64,
    pub commitment_nonce: String,
}

impl SubmitCompressedStateCommitmentRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeStateRentRebateRuntimeResult<()> {
        require_non_empty("market_id", &self.market_id)?;
        require_non_empty("contract_commitment", &self.contract_commitment)?;
        require_non_empty("account_commitment", &self.account_commitment)?;
        require_root("state_root_before", &self.state_root_before)?;
        require_root("compressed_state_root", &self.compressed_state_root)?;
        require_root("decompression_hint_root", &self.decompression_hint_root)?;
        require_root("access_pattern_root", &self.access_pattern_root)?;
        require_root("privacy_set_root", &self.privacy_set_root)?;
        require_root("rent_nullifier_root", &self.rent_nullifier_root)?;
        require_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        require_non_empty("commitment_nonce", &self.commitment_nonce)?;
        if self.max_user_fee_bps > config.target_max_rent_bps {
            return Err("max_user_fee_bps exceeds low-fee runtime target".to_string());
        }
        if self.storage_slots_after > self.storage_slots_before {
            return Err("storage_slots_after cannot exceed storage_slots_before".to_string());
        }
        if self.bytes_after > self.bytes_before {
            return Err("bytes_after cannot exceed bytes_before".to_string());
        }
        if self.bytes_before == 0 || self.storage_slots_before == 0 {
            return Err("state footprint before compression must be positive".to_string());
        }
        Ok(())
    }

    pub fn saved_bytes(&self) -> u64 {
        self.bytes_before.saturating_sub(self.bytes_after)
    }

    pub fn saved_slots(&self) -> u64 {
        self.storage_slots_before
            .saturating_sub(self.storage_slots_after)
    }

    pub fn compression_ratio_bps(&self) -> u64 {
        if self.bytes_before == 0 {
            return 0;
        }
        self.saved_bytes()
            .saturating_mul(PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_MAX_BPS)
            / self.bytes_before
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveLowFeeSponsorRequest {
    pub market_id: String,
    pub commitment_ids: Vec<String>,
    pub sponsor_commitment: String,
    pub sponsor_policy_root: String,
    pub budget_commitment_root: String,
    pub refund_address_commitment: String,
    pub max_cover_bps: u64,
    pub reserved_micro_units: u64,
    pub expires_at_height: u64,
    pub reservation_nonce: String,
}

impl ReserveLowFeeSponsorRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeStateRentRebateRuntimeResult<()> {
        require_non_empty("market_id", &self.market_id)?;
        require_unique("commitment_ids", &self.commitment_ids)?;
        require_non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        require_root("sponsor_policy_root", &self.sponsor_policy_root)?;
        require_root("budget_commitment_root", &self.budget_commitment_root)?;
        require_non_empty("refund_address_commitment", &self.refund_address_commitment)?;
        require_bps("max_cover_bps", self.max_cover_bps)?;
        require_non_empty("reservation_nonce", &self.reservation_nonce)?;
        if self.max_cover_bps < config.sponsor_cover_bps {
            return Err("max_cover_bps is below runtime sponsor cover target".to_string());
        }
        if self.reserved_micro_units == 0 {
            return Err("reserved_micro_units must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClaimRentRebateRequest {
    pub market_id: String,
    pub commitment_id: String,
    pub reservation_id: Option<String>,
    pub claimer_commitment: String,
    pub compression_proof_root: String,
    pub rent_paid_commitment_root: String,
    pub rebate_destination_root: String,
    pub claim_nullifier_root: String,
    pub eligible_rebate_bps: u64,
    pub requested_rebate_micro_units: u64,
    pub claim_height: u64,
    pub claim_nonce: String,
}

impl ClaimRentRebateRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeStateRentRebateRuntimeResult<()> {
        require_non_empty("market_id", &self.market_id)?;
        require_non_empty("commitment_id", &self.commitment_id)?;
        if let Some(reservation_id) = &self.reservation_id {
            require_non_empty("reservation_id", reservation_id)?;
        }
        require_non_empty("claimer_commitment", &self.claimer_commitment)?;
        require_root("compression_proof_root", &self.compression_proof_root)?;
        require_root("rent_paid_commitment_root", &self.rent_paid_commitment_root)?;
        require_root("rebate_destination_root", &self.rebate_destination_root)?;
        require_root("claim_nullifier_root", &self.claim_nullifier_root)?;
        require_bps("eligible_rebate_bps", self.eligible_rebate_bps)?;
        require_non_empty("claim_nonce", &self.claim_nonce)?;
        if self.eligible_rebate_bps < config.target_rebate_bps {
            return Err("eligible_rebate_bps is below runtime target".to_string());
        }
        if self.requested_rebate_micro_units == 0 {
            return Err("requested_rebate_micro_units must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueProofCacheVoucherRequest {
    pub claim_id: String,
    pub commitment_id: String,
    pub prover_commitment: String,
    pub proof_cache_key_root: String,
    pub proof_public_input_root: String,
    pub reusable_proof_commitment_root: String,
    pub verifier_program_root: String,
    pub voucher_value_micro_units: u64,
    pub max_lookup_fee_bps: u64,
    pub expires_at_height: u64,
    pub voucher_nonce: String,
}

impl IssueProofCacheVoucherRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeStateRentRebateRuntimeResult<()> {
        require_non_empty("claim_id", &self.claim_id)?;
        require_non_empty("commitment_id", &self.commitment_id)?;
        require_non_empty("prover_commitment", &self.prover_commitment)?;
        require_root("proof_cache_key_root", &self.proof_cache_key_root)?;
        require_root("proof_public_input_root", &self.proof_public_input_root)?;
        require_root(
            "reusable_proof_commitment_root",
            &self.reusable_proof_commitment_root,
        )?;
        require_root("verifier_program_root", &self.verifier_program_root)?;
        require_bps("max_lookup_fee_bps", self.max_lookup_fee_bps)?;
        require_non_empty("voucher_nonce", &self.voucher_nonce)?;
        if self.max_lookup_fee_bps > config.target_max_rent_bps {
            return Err("max_lookup_fee_bps exceeds low-fee runtime target".to_string());
        }
        if self.voucher_value_micro_units == 0 {
            return Err("voucher_value_micro_units must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildRentSettlementBatchRequest {
    pub market_ids: Vec<String>,
    pub commitment_ids: Vec<String>,
    pub claim_ids: Vec<String>,
    pub voucher_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub compressed_state_root: String,
    pub rebate_claim_root: String,
    pub sponsor_debit_root: String,
    pub proof_cache_root: String,
    pub settlement_manifest_root: String,
    pub aggregate_proof_root: String,
    pub max_batch_fee_bps: u64,
    pub batch_height: u64,
    pub batch_nonce: String,
}

impl BuildRentSettlementBatchRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeStateRentRebateRuntimeResult<()> {
        require_unique("market_ids", &self.market_ids)?;
        require_unique("commitment_ids", &self.commitment_ids)?;
        require_unique("claim_ids", &self.claim_ids)?;
        require_unique("voucher_ids", &self.voucher_ids)?;
        require_unique("reservation_ids", &self.reservation_ids)?;
        require_root("compressed_state_root", &self.compressed_state_root)?;
        require_root("rebate_claim_root", &self.rebate_claim_root)?;
        require_root("sponsor_debit_root", &self.sponsor_debit_root)?;
        require_root("proof_cache_root", &self.proof_cache_root)?;
        require_root("settlement_manifest_root", &self.settlement_manifest_root)?;
        require_root("aggregate_proof_root", &self.aggregate_proof_root)?;
        require_bps("max_batch_fee_bps", self.max_batch_fee_bps)?;
        require_non_empty("batch_nonce", &self.batch_nonce)?;
        if self.max_batch_fee_bps > config.target_max_rent_bps {
            return Err("max_batch_fee_bps exceeds low-fee runtime target".to_string());
        }
        if self.commitment_ids.len() < config.min_privacy_set_size {
            return Err("commitment_ids below min_privacy_set_size".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishRebateReceiptRequest {
    pub subject_id: String,
    pub receipt_kind: ReceiptKind,
    pub market_id: Option<String>,
    pub batch_id: Option<String>,
    pub claim_id: Option<String>,
    pub settlement_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub rebate_transfer_root: String,
    pub observer_set_root: String,
    pub paid_rebate_micro_units: u64,
    pub published_at_height: u64,
    pub receipt_nonce: String,
}

impl PublishRebateReceiptRequest {
    pub fn validate(&self) -> PrivateL2LowFeeStateRentRebateRuntimeResult<()> {
        require_non_empty("subject_id", &self.subject_id)?;
        if let Some(market_id) = &self.market_id {
            require_non_empty("market_id", market_id)?;
        }
        if let Some(batch_id) = &self.batch_id {
            require_non_empty("batch_id", batch_id)?;
        }
        if let Some(claim_id) = &self.claim_id {
            require_non_empty("claim_id", claim_id)?;
        }
        require_root("settlement_root", &self.settlement_root)?;
        require_root("state_root_before", &self.state_root_before)?;
        require_root("state_root_after", &self.state_root_after)?;
        require_root("rebate_transfer_root", &self.rebate_transfer_root)?;
        require_root("observer_set_root", &self.observer_set_root)?;
        require_non_empty("receipt_nonce", &self.receipt_nonce)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RentMarketRecord {
    pub market_id: String,
    pub request: OpenRentMarketRequest,
    pub status: RentMarketStatus,
    pub opened_at_height: u64,
    pub commitments: BTreeSet<String>,
    pub reservations: BTreeSet<String>,
    pub claims: BTreeSet<String>,
    pub market_root: String,
}

impl RentMarketRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompressedStateCommitmentRecord {
    pub commitment_id: String,
    pub request: SubmitCompressedStateCommitmentRequest,
    pub status: CommitmentStatus,
    pub compression_ratio_bps: u64,
    pub saved_bytes: u64,
    pub saved_slots: u64,
    pub expected_rebate_bps: u64,
    pub commitment_root: String,
}

impl CompressedStateCommitmentRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeSponsorReservationRecord {
    pub reservation_id: String,
    pub request: ReserveLowFeeSponsorRequest,
    pub status: SponsorReservationStatus,
    pub consumed_micro_units: u64,
    pub remaining_micro_units: u64,
    pub reservation_root: String,
}

impl LowFeeSponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RentRebateClaimRecord {
    pub claim_id: String,
    pub request: ClaimRentRebateRequest,
    pub status: RebateClaimStatus,
    pub approved_rebate_micro_units: u64,
    pub claim_root: String,
}

impl RentRebateClaimRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofCacheVoucherRecord {
    pub voucher_id: String,
    pub request: IssueProofCacheVoucherRequest,
    pub status: ProofCacheVoucherStatus,
    pub voucher_root: String,
}

impl ProofCacheVoucherRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RentSettlementBatchRecord {
    pub batch_id: String,
    pub request: BuildRentSettlementBatchRequest,
    pub status: SettlementBatchStatus,
    pub batch_score: u128,
    pub batch_root: String,
}

impl RentSettlementBatchRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateReceiptRecord {
    pub receipt_id: String,
    pub request: PublishRebateReceiptRequest,
    pub receipt_root: String,
}

impl RebateReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebatePayoutRecord {
    pub rebate_id: String,
    pub claim_id: String,
    pub receipt_id: String,
    pub paid_rebate_micro_units: u64,
    pub payout_root: String,
}

impl RebatePayoutRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub market_root: String,
    pub commitment_root: String,
    pub reservation_root: String,
    pub claim_root: String,
    pub voucher_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub markets: BTreeMap<String, RentMarketRecord>,
    pub commitments: BTreeMap<String, CompressedStateCommitmentRecord>,
    pub reservations: BTreeMap<String, LowFeeSponsorReservationRecord>,
    pub claims: BTreeMap<String, RentRebateClaimRecord>,
    pub vouchers: BTreeMap<String, ProofCacheVoucherRecord>,
    pub batches: BTreeMap<String, RentSettlementBatchRecord>,
    pub receipts: BTreeMap<String, RebateReceiptRecord>,
    pub rebates: BTreeMap<String, RebatePayoutRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        Self::new(Config::devnet()).expect("devnet state rent rebate config must validate")
    }

    pub fn new(config: Config) -> PrivateL2LowFeeStateRentRebateRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            markets: BTreeMap::new(),
            commitments: BTreeMap::new(),
            reservations: BTreeMap::new(),
            claims: BTreeMap::new(),
            vouchers: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn open_rent_market(
        &mut self,
        request: OpenRentMarketRequest,
    ) -> PrivateL2LowFeeStateRentRebateRuntimeResult<RentMarketRecord> {
        request.validate(&self.config)?;
        if self.markets.len() >= self.config.max_markets {
            return Err("state rent market capacity exhausted".to_string());
        }
        self.counters.market_counter = self.counters.market_counter.saturating_add(1);
        let market_id = rent_market_id(&request, self.counters.market_counter);
        let market_root = root_from_record(
            "PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-MARKET",
            &request.public_record(),
        );
        let record = RentMarketRecord {
            market_id: market_id.clone(),
            opened_at_height: request.opens_at_height,
            request,
            status: RentMarketStatus::Open,
            commitments: BTreeSet::new(),
            reservations: BTreeSet::new(),
            claims: BTreeSet::new(),
            market_root,
        };
        self.markets.insert(market_id, record.clone());
        Ok(record)
    }

    pub fn submit_compressed_state_commitment(
        &mut self,
        request: SubmitCompressedStateCommitmentRequest,
    ) -> PrivateL2LowFeeStateRentRebateRuntimeResult<CompressedStateCommitmentRecord> {
        request.validate(&self.config)?;
        if self.commitments.len() >= self.config.max_commitments {
            return Err("compressed state commitment capacity exhausted".to_string());
        }
        let market = self.require_market(&request.market_id)?;
        if !market.status.accepts_commitments() {
            return Err("state rent market is not accepting commitments".to_string());
        }
        if request.compression_ratio_bps() < market.request.min_compression_ratio_bps {
            return Err("compression ratio is below market minimum".to_string());
        }
        require_unique_nullifier(&self.consumed_nullifiers, &request.rent_nullifier_root)?;
        let market_request = market.request.clone();
        self.counters.commitment_counter = self.counters.commitment_counter.saturating_add(1);
        let commitment_id =
            compressed_state_commitment_id(&request, self.counters.commitment_counter);
        let expected_rebate_bps = expected_rebate_bps(&request, &market_request, &self.config);
        let commitment_root = root_from_record(
            "PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-COMMITMENT",
            &request.public_record(),
        );
        let record = CompressedStateCommitmentRecord {
            commitment_id: commitment_id.clone(),
            compression_ratio_bps: request.compression_ratio_bps(),
            saved_bytes: request.saved_bytes(),
            saved_slots: request.saved_slots(),
            expected_rebate_bps,
            request: request.clone(),
            status: CommitmentStatus::Submitted,
            commitment_root,
        };
        self.consumed_nullifiers
            .insert(request.rent_nullifier_root.clone());
        if let Some(market) = self.markets.get_mut(&request.market_id) {
            market.commitments.insert(commitment_id.clone());
        }
        self.commitments.insert(commitment_id, record.clone());
        Ok(record)
    }

    pub fn reserve_low_fee_sponsor(
        &mut self,
        request: ReserveLowFeeSponsorRequest,
    ) -> PrivateL2LowFeeStateRentRebateRuntimeResult<LowFeeSponsorReservationRecord> {
        request.validate(&self.config)?;
        if self.reservations.len() >= self.config.max_reservations {
            return Err("low-fee sponsor reservation capacity exhausted".to_string());
        }
        self.require_market(&request.market_id)?;
        for commitment_id in &request.commitment_ids {
            let commitment = self.require_commitment(commitment_id)?;
            if commitment.request.market_id != request.market_id {
                return Err(format!(
                    "commitment {commitment_id} belongs to a different market"
                ));
            }
            if !commitment.status.live() {
                return Err(format!("commitment {commitment_id} is not live"));
            }
        }
        self.counters.reservation_counter = self.counters.reservation_counter.saturating_add(1);
        let reservation_id = sponsor_reservation_id(&request, self.counters.reservation_counter);
        let reservation_root = root_from_record(
            "PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-SPONSOR-RESERVATION",
            &request.public_record(),
        );
        let record = LowFeeSponsorReservationRecord {
            reservation_id: reservation_id.clone(),
            remaining_micro_units: request.reserved_micro_units,
            request: request.clone(),
            status: SponsorReservationStatus::Reserved,
            consumed_micro_units: 0,
            reservation_root,
        };
        if let Some(market) = self.markets.get_mut(&request.market_id) {
            market.reservations.insert(reservation_id.clone());
        }
        for commitment_id in &request.commitment_ids {
            if let Some(commitment) = self.commitments.get_mut(commitment_id) {
                commitment.status = CommitmentStatus::Sponsored;
            }
        }
        self.reservations.insert(reservation_id, record.clone());
        Ok(record)
    }

    pub fn claim_rent_rebate(
        &mut self,
        request: ClaimRentRebateRequest,
    ) -> PrivateL2LowFeeStateRentRebateRuntimeResult<RentRebateClaimRecord> {
        request.validate(&self.config)?;
        if self.claims.len() >= self.config.max_claims {
            return Err("rent rebate claim capacity exhausted".to_string());
        }
        self.require_market(&request.market_id)?;
        let commitment = self.require_commitment(&request.commitment_id)?;
        if commitment.request.market_id != request.market_id {
            return Err("claim market_id does not match commitment market_id".to_string());
        }
        require_unique_nullifier(&self.consumed_nullifiers, &request.claim_nullifier_root)?;
        if let Some(reservation_id) = &request.reservation_id {
            let reservation = self.require_reservation(reservation_id)?;
            if reservation.request.market_id != request.market_id {
                return Err("reservation market_id does not match claim market_id".to_string());
            }
            if !reservation
                .request
                .commitment_ids
                .iter()
                .any(|id| id == &request.commitment_id)
            {
                return Err("reservation does not cover commitment_id".to_string());
            }
        }
        let expected_rebate_bps = commitment.expected_rebate_bps;
        self.counters.claim_counter = self.counters.claim_counter.saturating_add(1);
        let claim_id = rent_rebate_claim_id(&request, self.counters.claim_counter);
        let approved_rebate_micro_units = approved_rebate_amount(&request, expected_rebate_bps);
        let claim_root = root_from_record(
            "PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-CLAIM",
            &request.public_record(),
        );
        let record = RentRebateClaimRecord {
            claim_id: claim_id.clone(),
            approved_rebate_micro_units,
            request: request.clone(),
            status: RebateClaimStatus::Submitted,
            claim_root,
        };
        self.consumed_nullifiers
            .insert(request.claim_nullifier_root.clone());
        if let Some(market) = self.markets.get_mut(&request.market_id) {
            market.claims.insert(claim_id.clone());
        }
        if let Some(commitment) = self.commitments.get_mut(&request.commitment_id) {
            commitment.status = CommitmentStatus::Claimable;
        }
        self.claims.insert(claim_id, record.clone());
        Ok(record)
    }

    pub fn issue_proof_cache_voucher(
        &mut self,
        request: IssueProofCacheVoucherRequest,
    ) -> PrivateL2LowFeeStateRentRebateRuntimeResult<ProofCacheVoucherRecord> {
        request.validate(&self.config)?;
        if self.vouchers.len() >= self.config.max_vouchers {
            return Err("proof-cache voucher capacity exhausted".to_string());
        }
        let claim = self.require_claim(&request.claim_id)?;
        if claim.request.commitment_id != request.commitment_id {
            return Err("voucher commitment_id does not match claim commitment_id".to_string());
        }
        self.require_commitment(&request.commitment_id)?;
        self.counters.voucher_counter = self.counters.voucher_counter.saturating_add(1);
        let voucher_id = proof_cache_voucher_id(&request, self.counters.voucher_counter);
        let voucher_root = root_from_record(
            "PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-PROOF-CACHE-VOUCHER",
            &request.public_record(),
        );
        let record = ProofCacheVoucherRecord {
            voucher_id: voucher_id.clone(),
            request: request.clone(),
            status: ProofCacheVoucherStatus::Open,
            voucher_root,
        };
        if let Some(claim) = self.claims.get_mut(&request.claim_id) {
            claim.status = RebateClaimStatus::VoucherAttached;
        }
        if let Some(commitment) = self.commitments.get_mut(&request.commitment_id) {
            commitment.status = CommitmentStatus::ProofCached;
        }
        self.vouchers.insert(voucher_id, record.clone());
        Ok(record)
    }

    pub fn build_settlement_batch(
        &mut self,
        request: BuildRentSettlementBatchRequest,
    ) -> PrivateL2LowFeeStateRentRebateRuntimeResult<RentSettlementBatchRecord> {
        request.validate(&self.config)?;
        if self.batches.len() >= self.config.max_batches {
            return Err("rent settlement batch capacity exhausted".to_string());
        }
        for market_id in &request.market_ids {
            self.require_market(market_id)?;
        }
        for commitment_id in &request.commitment_ids {
            self.require_commitment(commitment_id)?;
        }
        for claim_id in &request.claim_ids {
            self.require_claim(claim_id)?;
        }
        for voucher_id in &request.voucher_ids {
            self.require_voucher(voucher_id)?;
        }
        for reservation_id in &request.reservation_ids {
            self.require_reservation(reservation_id)?;
        }
        self.counters.batch_counter = self.counters.batch_counter.saturating_add(1);
        let score = settlement_batch_score(&request, &self.commitments, &self.claims);
        let batch_id = settlement_batch_id(&request, score, self.counters.batch_counter);
        let batch_root = root_from_record(
            "PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-SETTLEMENT-BATCH",
            &request.public_record(),
        );
        let record = RentSettlementBatchRecord {
            batch_id: batch_id.clone(),
            request: request.clone(),
            status: SettlementBatchStatus::SettlementReady,
            batch_score: score,
            batch_root,
        };
        for commitment_id in &request.commitment_ids {
            if let Some(commitment) = self.commitments.get_mut(commitment_id) {
                commitment.status = CommitmentStatus::Batched;
            }
        }
        for claim_id in &request.claim_ids {
            if let Some(claim) = self.claims.get_mut(claim_id) {
                claim.status = RebateClaimStatus::Batched;
            }
        }
        for voucher_id in &request.voucher_ids {
            if let Some(voucher) = self.vouchers.get_mut(voucher_id) {
                voucher.status = ProofCacheVoucherStatus::Attached;
            }
        }
        self.batches.insert(batch_id, record.clone());
        Ok(record)
    }

    pub fn publish_rebate_receipt(
        &mut self,
        request: PublishRebateReceiptRequest,
    ) -> PrivateL2LowFeeStateRentRebateRuntimeResult<RebateReceiptRecord> {
        request.validate()?;
        if self.receipts.len() >= self.config.max_receipts {
            return Err("rebate receipt capacity exhausted".to_string());
        }
        if let Some(market_id) = &request.market_id {
            self.require_market(market_id)?;
        }
        if let Some(batch_id) = &request.batch_id {
            self.require_batch(batch_id)?;
        }
        if let Some(claim_id) = &request.claim_id {
            self.require_claim(claim_id)?;
        }
        self.counters.receipt_counter = self.counters.receipt_counter.saturating_add(1);
        let receipt_id = rebate_receipt_id(&request, self.counters.receipt_counter);
        let receipt_root = root_from_record(
            "PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-RECEIPT",
            &request.public_record(),
        );
        let record = RebateReceiptRecord {
            receipt_id: receipt_id.clone(),
            request: request.clone(),
            receipt_root,
        };
        match request.receipt_kind {
            ReceiptKind::SettlementPublished => {
                if let Some(batch_id) = &request.batch_id {
                    if let Some(batch) = self.batches.get_mut(batch_id) {
                        batch.status = SettlementBatchStatus::Settled;
                    }
                }
            }
            ReceiptKind::RebatePaid => {
                if let Some(claim_id) = &request.claim_id {
                    if let Some(claim) = self.claims.get_mut(claim_id) {
                        claim.status = RebateClaimStatus::Paid;
                    }
                }
            }
            ReceiptKind::MarketSlashed => {
                if let Some(market_id) = &request.market_id {
                    if let Some(market) = self.markets.get_mut(market_id) {
                        market.status = RentMarketStatus::Slashed;
                    }
                }
            }
            _ => {}
        }
        self.receipts.insert(receipt_id, record.clone());
        Ok(record)
    }

    pub fn publish_rebate_payout(
        &mut self,
        claim_id: String,
        receipt_id: String,
    ) -> PrivateL2LowFeeStateRentRebateRuntimeResult<RebatePayoutRecord> {
        if self.rebates.len() >= self.config.max_receipts {
            return Err("rebate payout capacity exhausted".to_string());
        }
        let approved_rebate_micro_units =
            self.require_claim(&claim_id)?.approved_rebate_micro_units;
        let receipt_record = self.require_receipt(&receipt_id)?;
        if receipt_record.request.claim_id.as_ref() != Some(&claim_id) {
            return Err("receipt does not reference claim_id".to_string());
        }
        let paid_rebate_micro_units = receipt_record.request.paid_rebate_micro_units;
        self.counters.rebate_counter = self.counters.rebate_counter.saturating_add(1);
        let payload = json!({
            "claim_id": &claim_id,
            "receipt_id": &receipt_id,
            "paid_rebate_micro_units": paid_rebate_micro_units,
            "approved_rebate_micro_units": approved_rebate_micro_units,
            "sequence": self.counters.rebate_counter,
        });
        let rebate_id = rebate_payout_id(&payload, self.counters.rebate_counter);
        let payout_root = root_from_record("PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-PAYOUT", &payload);
        let record = RebatePayoutRecord {
            rebate_id: rebate_id.clone(),
            claim_id: claim_id.clone(),
            receipt_id,
            paid_rebate_micro_units,
            payout_root,
        };
        if let Some(claim) = self.claims.get_mut(&claim_id) {
            claim.status = RebateClaimStatus::Paid;
        }
        self.rebates.insert(rebate_id, record.clone());
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let market_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-MARKETS",
            &self
                .markets
                .values()
                .map(RentMarketRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let commitment_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-COMMITMENTS",
            &self
                .commitments
                .values()
                .map(CompressedStateCommitmentRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let reservation_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-RESERVATIONS",
            &self
                .reservations
                .values()
                .map(LowFeeSponsorReservationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let claim_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-CLAIMS",
            &self
                .claims
                .values()
                .map(RentRebateClaimRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let voucher_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-VOUCHERS",
            &self
                .vouchers
                .values()
                .map(ProofCacheVoucherRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let batch_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-BATCHES",
            &self
                .batches
                .values()
                .map(RentSettlementBatchRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let receipt_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-RECEIPTS",
            &self
                .receipts
                .values()
                .map(RebateReceiptRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let rebate_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-PAYOUTS",
            &self
                .rebates
                .values()
                .map(RebatePayoutRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-NULLIFIERS",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!(nullifier))
                .collect::<Vec<_>>(),
        );
        let state_record = json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "market_root": market_root,
            "commitment_root": commitment_root,
            "reservation_root": reservation_root,
            "claim_root": claim_root,
            "voucher_root": voucher_root,
            "batch_root": batch_root,
            "receipt_root": receipt_root,
            "rebate_root": rebate_root,
            "nullifier_root": nullifier_root,
        });
        let state_root = state_root_from_record(&state_record);
        Roots {
            market_root,
            commitment_root,
            reservation_root,
            claim_root,
            voucher_root,
            batch_root,
            receipt_root,
            rebate_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "hash_suite": self.config.hash_suite,
            "pq_auth_suite": self.config.pq_auth_suite,
            "compression_suite": self.config.compression_suite,
            "proof_suite": self.config.proof_suite,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(map) = record.as_object_mut() {
            map.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn require_market(
        &self,
        market_id: &str,
    ) -> PrivateL2LowFeeStateRentRebateRuntimeResult<&RentMarketRecord> {
        self.markets
            .get(market_id)
            .ok_or_else(|| format!("unknown state rent market {market_id}"))
    }

    fn require_commitment(
        &self,
        commitment_id: &str,
    ) -> PrivateL2LowFeeStateRentRebateRuntimeResult<&CompressedStateCommitmentRecord> {
        self.commitments
            .get(commitment_id)
            .ok_or_else(|| format!("unknown compressed state commitment {commitment_id}"))
    }

    fn require_reservation(
        &self,
        reservation_id: &str,
    ) -> PrivateL2LowFeeStateRentRebateRuntimeResult<&LowFeeSponsorReservationRecord> {
        self.reservations
            .get(reservation_id)
            .ok_or_else(|| format!("unknown low-fee sponsor reservation {reservation_id}"))
    }

    fn require_claim(
        &self,
        claim_id: &str,
    ) -> PrivateL2LowFeeStateRentRebateRuntimeResult<&RentRebateClaimRecord> {
        self.claims
            .get(claim_id)
            .ok_or_else(|| format!("unknown rent rebate claim {claim_id}"))
    }

    fn require_voucher(
        &self,
        voucher_id: &str,
    ) -> PrivateL2LowFeeStateRentRebateRuntimeResult<&ProofCacheVoucherRecord> {
        self.vouchers
            .get(voucher_id)
            .ok_or_else(|| format!("unknown proof-cache voucher {voucher_id}"))
    }

    fn require_batch(
        &self,
        batch_id: &str,
    ) -> PrivateL2LowFeeStateRentRebateRuntimeResult<&RentSettlementBatchRecord> {
        self.batches
            .get(batch_id)
            .ok_or_else(|| format!("unknown rent settlement batch {batch_id}"))
    }

    fn require_receipt(
        &self,
        receipt_id: &str,
    ) -> PrivateL2LowFeeStateRentRebateRuntimeResult<&RebateReceiptRecord> {
        self.receipts
            .get(receipt_id)
            .ok_or_else(|| format!("unknown rebate receipt {receipt_id}"))
    }
}

pub type Runtime = State;

pub fn rent_market_id(request: &OpenRentMarketRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-MARKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(request.market_kind.as_str()),
            HashPart::Str(&request.market_operator_commitment),
            HashPart::Str(&request.contract_class_root),
            HashPart::Str(&request.state_namespace_root),
            HashPart::Str(&request.market_nonce),
        ],
        32,
    )
}

pub fn compressed_state_commitment_id(
    request: &SubmitCompressedStateCommitmentRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.market_id),
            HashPart::Str(&request.contract_commitment),
            HashPart::Str(&request.account_commitment),
            HashPart::Str(request.compression_kind.as_str()),
            HashPart::Str(&request.state_root_before),
            HashPart::Str(&request.compressed_state_root),
            HashPart::Str(&request.rent_nullifier_root),
            HashPart::Str(&request.commitment_nonce),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(request: &ReserveLowFeeSponsorRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.market_id),
            HashPart::Str(&id_list_root("commitments", &request.commitment_ids)),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.budget_commitment_root),
            HashPart::Str(&request.reservation_nonce),
        ],
        32,
    )
}

pub fn rent_rebate_claim_id(request: &ClaimRentRebateRequest, sequence: u64) -> String {
    let reservation = request.reservation_id.as_deref().unwrap_or("none");
    domain_hash(
        "PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-CLAIM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.market_id),
            HashPart::Str(&request.commitment_id),
            HashPart::Str(reservation),
            HashPart::Str(&request.claimer_commitment),
            HashPart::Str(&request.claim_nullifier_root),
            HashPart::Str(&request.claim_nonce),
        ],
        32,
    )
}

pub fn proof_cache_voucher_id(request: &IssueProofCacheVoucherRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-PROOF-CACHE-VOUCHER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.claim_id),
            HashPart::Str(&request.commitment_id),
            HashPart::Str(&request.prover_commitment),
            HashPart::Str(&request.proof_cache_key_root),
            HashPart::Str(&request.voucher_nonce),
        ],
        32,
    )
}

pub fn settlement_batch_id(
    request: &BuildRentSettlementBatchRequest,
    score: u128,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-SETTLEMENT-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&id_list_root("markets", &request.market_ids)),
            HashPart::Str(&id_list_root("commitments", &request.commitment_ids)),
            HashPart::Str(&id_list_root("claims", &request.claim_ids)),
            HashPart::Str(&id_list_root("vouchers", &request.voucher_ids)),
            HashPart::Str(&request.settlement_manifest_root),
            HashPart::Int(score as i128),
            HashPart::Str(&request.batch_nonce),
        ],
        32,
    )
}

pub fn rebate_receipt_id(request: &PublishRebateReceiptRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.subject_id),
            HashPart::Str(request.receipt_kind.as_str()),
            HashPart::Str(&request.settlement_root),
            HashPart::Str(&request.state_root_after),
            HashPart::Str(&request.receipt_nonce),
        ],
        32,
    )
}

pub fn rebate_payout_id(payload: &Value, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-PAYOUT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(domain, payload)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-STATE", record)
}

fn id_list_root(domain: &str, ids: &[String]) -> String {
    public_record_root(
        &format!("PRIVATE-L2-LOW-FEE-STATE-RENT-REBATE-ID-LIST-{domain}"),
        &ids.iter().map(|id| json!(id)).collect::<Vec<_>>(),
    )
}

fn expected_rebate_bps(
    request: &SubmitCompressedStateCommitmentRequest,
    market: &OpenRentMarketRequest,
    config: &Config,
) -> u64 {
    let compression_component = request
        .compression_ratio_bps()
        .saturating_mul(request.compression_kind.expected_rebate_multiplier_bps())
        / PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_MAX_BPS;
    compression_component
        .max(market.target_rebate_bps)
        .max(config.target_rebate_bps)
        .min(PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_MAX_BPS)
}

fn approved_rebate_amount(request: &ClaimRentRebateRequest, expected_rebate_bps: u64) -> u64 {
    request
        .requested_rebate_micro_units
        .saturating_mul(request.eligible_rebate_bps.min(expected_rebate_bps))
        / PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_MAX_BPS
}

fn settlement_batch_score(
    request: &BuildRentSettlementBatchRequest,
    commitments: &BTreeMap<String, CompressedStateCommitmentRecord>,
    claims: &BTreeMap<String, RentRebateClaimRecord>,
) -> u128 {
    let saved_bytes = request
        .commitment_ids
        .iter()
        .filter_map(|id| commitments.get(id))
        .map(|record| record.saved_bytes as u128)
        .sum::<u128>();
    let approved_rebates = request
        .claim_ids
        .iter()
        .filter_map(|id| claims.get(id))
        .map(|record| record.approved_rebate_micro_units as u128)
        .sum::<u128>();
    let privacy_bonus = request.commitment_ids.len() as u128 * 1_000_000;
    let fee_penalty = request.max_batch_fee_bps as u128 * 10_000;
    saved_bytes
        .saturating_mul(100)
        .saturating_add(approved_rebates)
        .saturating_add(privacy_bonus)
        .saturating_sub(fee_penalty)
}

fn require_non_empty(field: &str, value: &str) -> PrivateL2LowFeeStateRentRebateRuntimeResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn require_root(field: &str, value: &str) -> PrivateL2LowFeeStateRentRebateRuntimeResult<()> {
    require_non_empty(field, value)?;
    if value.len() < 16 {
        return Err(format!("{field} must look like a commitment root"));
    }
    Ok(())
}

fn require_positive(field: &str, value: usize) -> PrivateL2LowFeeStateRentRebateRuntimeResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn require_bps(field: &str, value: u64) -> PrivateL2LowFeeStateRentRebateRuntimeResult<()> {
    if value > PRIVATE_L2_LOW_FEE_STATE_RENT_REBATE_RUNTIME_MAX_BPS {
        Err(format!("{field} exceeds basis point maximum"))
    } else {
        Ok(())
    }
}

fn require_unique(
    field: &str,
    values: &[String],
) -> PrivateL2LowFeeStateRentRebateRuntimeResult<()> {
    let mut seen = BTreeSet::new();
    if values.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    for value in values {
        require_non_empty(field, value)?;
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicate value {value}"));
        }
    }
    Ok(())
}

fn require_unique_nullifier(
    consumed: &BTreeSet<String>,
    nullifier: &str,
) -> PrivateL2LowFeeStateRentRebateRuntimeResult<()> {
    require_root("nullifier", nullifier)?;
    if consumed.contains(nullifier) {
        Err(format!("nullifier already consumed {nullifier}"))
    } else {
        Ok(())
    }
}
