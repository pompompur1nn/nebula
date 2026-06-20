use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeeRecursiveDaSettlementRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_RECURSIVE_DA_SETTLEMENT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-recursive-da-settlement-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_DA_SETTLEMENT_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_DA_SETTLEMENT_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_DA_SETTLEMENT_RUNTIME_PQ_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_DA_SETTLEMENT_RUNTIME_DA_SUITE: &str =
    "encrypted-erasure-coded-da-recursive-availability-v1";
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_DA_SETTLEMENT_RUNTIME_PROOF_SUITE: &str =
    "recursive-stark-da-settlement-compressor-v1";
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_DA_SETTLEMENT_RUNTIME_REBATE_SCHEME: &str =
    "anonymous-low-fee-rebate-commitment-v1";
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_DA_SETTLEMENT_RUNTIME_DEVNET_HEIGHT: u64 = 484_000;
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_DA_SETTLEMENT_RUNTIME_MAX_BPS: u64 = 10_000;
pub const DEFAULT_MAX_DA_LANES: usize = 64;
pub const DEFAULT_MAX_PAYLOADS: usize = 2_097_152;
pub const DEFAULT_MAX_PROOF_JOBS: usize = 1_048_576;
pub const DEFAULT_MAX_SPONSOR_VOUCHERS: usize = 1_048_576;
pub const DEFAULT_MAX_COMPRESSION_BATCHES: usize = 262_144;
pub const DEFAULT_MAX_SETTLEMENT_RECEIPTS: usize = 2_097_152;
pub const DEFAULT_MAX_REBATES: usize = 1_048_576;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 8;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_200;
pub const DEFAULT_JOB_TTL_BLOCKS: u64 = 16;
pub const DEFAULT_VOUCHER_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_BATCH_TTL_BLOCKS: u64 = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaLaneKind {
    EncryptedWitness,
    ErasureShard,
    StateDiff,
    ContractCalldata,
    DefiNetting,
    MoneroAnchor,
    RecursiveProof,
    EmergencyEscape,
}

impl DaLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EncryptedWitness => "encrypted_witness",
            Self::ErasureShard => "erasure_shard",
            Self::StateDiff => "state_diff",
            Self::ContractCalldata => "contract_calldata",
            Self::DefiNetting => "defi_netting",
            Self::MoneroAnchor => "monero_anchor",
            Self::RecursiveProof => "recursive_proof",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn latency_weight(self) -> u64 {
        match self {
            Self::EmergencyEscape => 10_000,
            Self::MoneroAnchor => 9_400,
            Self::DefiNetting => 9_000,
            Self::ContractCalldata => 8_700,
            Self::RecursiveProof => 8_500,
            Self::StateDiff => 8_200,
            Self::EncryptedWitness => 8_000,
            Self::ErasureShard => 7_700,
        }
    }

    pub fn defi_compatible(self) -> bool {
        matches!(
            self,
            Self::DefiNetting | Self::ContractCalldata | Self::StateDiff
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Congested,
    Sponsored,
    SettlementOnly,
    Paused,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Congested => "congested",
            Self::Sponsored => "sponsored",
            Self::SettlementOnly => "settlement_only",
            Self::Paused => "paused",
        }
    }

    pub fn accepting_payloads(self) -> bool {
        matches!(self, Self::Open | Self::Congested | Self::Sponsored)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadStatus {
    Submitted,
    Sampled,
    QueuedForProof,
    Compressed,
    Settled,
    Rejected,
    Expired,
}

impl PayloadStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Sampled => "sampled",
            Self::QueuedForProof => "queued_for_proof",
            Self::Compressed => "compressed",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Sampled | Self::QueuedForProof | Self::Compressed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofJobKind {
    DaInclusion,
    AvailabilitySampling,
    StateTransition,
    ContractExecution,
    DefiNetting,
    MoneroAnchor,
    RecursiveAggregate,
    SettlementReceipt,
}

impl ProofJobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DaInclusion => "da_inclusion",
            Self::AvailabilitySampling => "availability_sampling",
            Self::StateTransition => "state_transition",
            Self::ContractExecution => "contract_execution",
            Self::DefiNetting => "defi_netting",
            Self::MoneroAnchor => "monero_anchor",
            Self::RecursiveAggregate => "recursive_aggregate",
            Self::SettlementReceipt => "settlement_receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofJobStatus {
    Queued,
    Sponsored,
    Proving,
    Aggregated,
    Settled,
    Failed,
    Expired,
}

impl ProofJobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Sponsored => "sponsored",
            Self::Proving => "proving",
            Self::Aggregated => "aggregated",
            Self::Settled => "settled",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }

    pub fn batchable(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Sponsored | Self::Proving | Self::Aggregated
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoucherStatus {
    Issued,
    Bound,
    Claimed,
    Settled,
    Rebated,
    Expired,
    Revoked,
}

impl VoucherStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Bound => "bound",
            Self::Claimed => "claimed",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionCodec {
    CanonicalJson,
    ZstdDictionary,
    PoseidonDelta,
    ErasureShardPack,
    RecursiveTranscript,
}

impl CompressionCodec {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CanonicalJson => "canonical_json",
            Self::ZstdDictionary => "zstd_dictionary",
            Self::PoseidonDelta => "poseidon_delta",
            Self::ErasureShardPack => "erasure_shard_pack",
            Self::RecursiveTranscript => "recursive_transcript",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Packed,
    Proved,
    Settled,
    Rebated,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Packed => "packed",
            Self::Proved => "proved",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Reorged,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Reorged => "reorged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accrued,
    Claimable,
    Paid,
    Donated,
    Expired,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accrued => "accrued",
            Self::Claimable => "claimable",
            Self::Paid => "paid",
            Self::Donated => "donated",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub max_da_lanes: usize,
    pub max_payloads: usize,
    pub max_proof_jobs: usize,
    pub max_sponsor_vouchers: usize,
    pub max_compression_batches: usize,
    pub max_settlement_receipts: usize,
    pub max_rebates: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub job_ttl_blocks: u64,
    pub voucher_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub defi_compatibility: bool,
    pub monero_anchor_compatibility: bool,
    pub emergency_lane_enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            max_da_lanes: DEFAULT_MAX_DA_LANES,
            max_payloads: DEFAULT_MAX_PAYLOADS,
            max_proof_jobs: DEFAULT_MAX_PROOF_JOBS,
            max_sponsor_vouchers: DEFAULT_MAX_SPONSOR_VOUCHERS,
            max_compression_batches: DEFAULT_MAX_COMPRESSION_BATCHES,
            max_settlement_receipts: DEFAULT_MAX_SETTLEMENT_RECEIPTS,
            max_rebates: DEFAULT_MAX_REBATES,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            job_ttl_blocks: DEFAULT_JOB_TTL_BLOCKS,
            voucher_ttl_blocks: DEFAULT_VOUCHER_TTL_BLOCKS,
            batch_ttl_blocks: DEFAULT_BATCH_TTL_BLOCKS,
            defi_compatibility: true,
            monero_anchor_compatibility: true,
            emergency_lane_enabled: true,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": PRIVATE_L2_LOW_FEE_RECURSIVE_DA_SETTLEMENT_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_LOW_FEE_RECURSIVE_DA_SETTLEMENT_RUNTIME_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_LOW_FEE_RECURSIVE_DA_SETTLEMENT_RUNTIME_HASH_SUITE,
            "pq_suite": PRIVATE_L2_LOW_FEE_RECURSIVE_DA_SETTLEMENT_RUNTIME_PQ_SUITE,
            "da_suite": PRIVATE_L2_LOW_FEE_RECURSIVE_DA_SETTLEMENT_RUNTIME_DA_SUITE,
            "proof_suite": PRIVATE_L2_LOW_FEE_RECURSIVE_DA_SETTLEMENT_RUNTIME_PROOF_SUITE,
            "rebate_scheme": PRIVATE_L2_LOW_FEE_RECURSIVE_DA_SETTLEMENT_RUNTIME_REBATE_SCHEME,
            "max_da_lanes": self.max_da_lanes,
            "max_payloads": self.max_payloads,
            "max_proof_jobs": self.max_proof_jobs,
            "max_sponsor_vouchers": self.max_sponsor_vouchers,
            "max_compression_batches": self.max_compression_batches,
            "max_settlement_receipts": self.max_settlement_receipts,
            "max_rebates": self.max_rebates,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "job_ttl_blocks": self.job_ttl_blocks,
            "voucher_ttl_blocks": self.voucher_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "defi_compatibility": self.defi_compatibility,
            "monero_anchor_compatibility": self.monero_anchor_compatibility,
            "emergency_lane_enabled": self.emergency_lane_enabled,
        })
    }

    pub fn validate(&self) -> PrivateL2LowFeeRecursiveDaSettlementRuntimeResult<()> {
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_capacity("max_da_lanes", self.max_da_lanes)?;
        ensure_capacity("max_payloads", self.max_payloads)?;
        ensure_capacity("max_proof_jobs", self.max_proof_jobs)?;
        ensure_capacity("max_sponsor_vouchers", self.max_sponsor_vouchers)?;
        ensure_capacity("max_compression_batches", self.max_compression_batches)?;
        ensure_capacity("max_settlement_receipts", self.max_settlement_receipts)?;
        ensure_capacity("max_rebates", self.max_rebates)?;
        ensure_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        ensure_bps("target_rebate_bps", self.target_rebate_bps)?;
        ensure_bps("sponsor_cover_bps", self.sponsor_cover_bps)?;
        if self.min_privacy_set_size == 0 {
            return Err("min_privacy_set_size must be non-zero".to_string());
        }
        if self.batch_privacy_set_size < self.min_privacy_set_size {
            return Err("batch_privacy_set_size must cover min_privacy_set_size".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("min_pq_security_bits below runtime floor".to_string());
        }
        Ok(())
    }

    pub fn root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub payloads_submitted: u64,
    pub payload_bytes: u64,
    pub proof_jobs_created: u64,
    pub proof_jobs_settled: u64,
    pub vouchers_issued: u64,
    pub vouchers_claimed: u64,
    pub compression_batches: u64,
    pub compressed_bytes: u64,
    pub settlement_receipts: u64,
    pub rebates_accrued: u64,
    pub rebates_paid: u64,
    pub user_fee_micro_units: u64,
    pub sponsor_fee_micro_units: u64,
    pub rebate_micro_units: u64,
    pub nullifier_fence_hits: u64,
    pub privacy_set_merges: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "payloads_submitted": self.payloads_submitted,
            "payload_bytes": self.payload_bytes,
            "proof_jobs_created": self.proof_jobs_created,
            "proof_jobs_settled": self.proof_jobs_settled,
            "vouchers_issued": self.vouchers_issued,
            "vouchers_claimed": self.vouchers_claimed,
            "compression_batches": self.compression_batches,
            "compressed_bytes": self.compressed_bytes,
            "settlement_receipts": self.settlement_receipts,
            "rebates_accrued": self.rebates_accrued,
            "rebates_paid": self.rebates_paid,
            "user_fee_micro_units": self.user_fee_micro_units,
            "sponsor_fee_micro_units": self.sponsor_fee_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "nullifier_fence_hits": self.nullifier_fence_hits,
            "privacy_set_merges": self.privacy_set_merges,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub lane_root: String,
    pub payload_root: String,
    pub proof_job_root: String,
    pub voucher_root: String,
    pub compression_batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub privacy_set_root: String,
    pub nullifier_fence_root: String,
    pub public_record_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "payload_root": self.payload_root,
            "proof_job_root": self.proof_job_root,
            "voucher_root": self.voucher_root,
            "compression_batch_root": self.compression_batch_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "privacy_set_root": self.privacy_set_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "public_record_root": self.public_record_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-ROOTS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaSettlementLane {
    pub lane_id: String,
    pub kind: DaLaneKind,
    pub status: LaneStatus,
    pub operator_commitment: String,
    pub fee_asset_id: String,
    pub max_payload_bytes: u64,
    pub max_user_fee_micro_units: u64,
    pub sponsor_pool_commitment: String,
    pub privacy_set_id: String,
    pub availability_quorum_root: String,
    pub recursive_verifier_root: String,
    pub opened_height: u64,
    pub nonce: u64,
}

impl DaSettlementLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: DaLaneKind,
        status: LaneStatus,
        operator_commitment: &str,
        fee_asset_id: &str,
        max_payload_bytes: u64,
        max_user_fee_micro_units: u64,
        sponsor_pool_commitment: &str,
        privacy_set_id: &str,
        availability_quorum_root: &str,
        recursive_verifier_root: &str,
        opened_height: u64,
        nonce: u64,
    ) -> Self {
        let lane_id = lane_id(
            kind,
            operator_commitment,
            fee_asset_id,
            privacy_set_id,
            opened_height,
            nonce,
        );
        Self {
            lane_id,
            kind,
            status,
            operator_commitment: operator_commitment.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            max_payload_bytes,
            max_user_fee_micro_units,
            sponsor_pool_commitment: sponsor_pool_commitment.to_string(),
            privacy_set_id: privacy_set_id.to_string(),
            availability_quorum_root: availability_quorum_root.to_string(),
            recursive_verifier_root: recursive_verifier_root.to_string(),
            opened_height,
            nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "operator_commitment": self.operator_commitment,
            "fee_asset_id": self.fee_asset_id,
            "max_payload_bytes": self.max_payload_bytes,
            "max_user_fee_micro_units": self.max_user_fee_micro_units,
            "sponsor_pool_commitment": self.sponsor_pool_commitment,
            "privacy_set_id": self.privacy_set_id,
            "availability_quorum_root": self.availability_quorum_root,
            "recursive_verifier_root": self.recursive_verifier_root,
            "opened_height": self.opened_height,
            "nonce": self.nonce,
            "latency_weight": self.kind.latency_weight(),
            "defi_compatible": self.kind.defi_compatible(),
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-LANE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaPayload {
    pub payload_id: String,
    pub lane_id: String,
    pub submitter_commitment: String,
    pub payload_commitment: String,
    pub encrypted_payload_root: String,
    pub erasure_root: String,
    pub public_inputs_root: String,
    pub data_bytes: u64,
    pub max_fee_micro_units: u64,
    pub privacy_set_id: String,
    pub nullifier_fence_id: String,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub status: PayloadStatus,
    pub nonce: u64,
}

impl DaPayload {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: &str,
        submitter_commitment: &str,
        payload_commitment: &str,
        encrypted_payload_root: &str,
        erasure_root: &str,
        public_inputs_root: &str,
        data_bytes: u64,
        max_fee_micro_units: u64,
        privacy_set_id: &str,
        nullifier_fence_id: &str,
        submitted_height: u64,
        expires_height: u64,
        status: PayloadStatus,
        nonce: u64,
    ) -> Self {
        let payload_id = da_payload_id(
            lane_id,
            submitter_commitment,
            payload_commitment,
            encrypted_payload_root,
            submitted_height,
            nonce,
        );
        Self {
            payload_id,
            lane_id: lane_id.to_string(),
            submitter_commitment: submitter_commitment.to_string(),
            payload_commitment: payload_commitment.to_string(),
            encrypted_payload_root: encrypted_payload_root.to_string(),
            erasure_root: erasure_root.to_string(),
            public_inputs_root: public_inputs_root.to_string(),
            data_bytes,
            max_fee_micro_units,
            privacy_set_id: privacy_set_id.to_string(),
            nullifier_fence_id: nullifier_fence_id.to_string(),
            submitted_height,
            expires_height,
            status,
            nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "payload_id": self.payload_id,
            "lane_id": self.lane_id,
            "submitter_commitment": self.submitter_commitment,
            "payload_commitment": self.payload_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "erasure_root": self.erasure_root,
            "public_inputs_root": self.public_inputs_root,
            "data_bytes": self.data_bytes,
            "max_fee_micro_units": self.max_fee_micro_units,
            "privacy_set_id": self.privacy_set_id,
            "nullifier_fence_id": self.nullifier_fence_id,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "nonce": self.nonce,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-PAYLOAD",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecursiveProofJob {
    pub job_id: String,
    pub kind: ProofJobKind,
    pub payload_ids: Vec<String>,
    pub parent_job_ids: Vec<String>,
    pub prover_commitment: String,
    pub input_root: String,
    pub witness_root: String,
    pub proof_root: String,
    pub recursion_depth: u64,
    pub target_pq_security_bits: u16,
    pub max_fee_micro_units: u64,
    pub sponsor_voucher_id: Option<String>,
    pub created_height: u64,
    pub expires_height: u64,
    pub status: ProofJobStatus,
    pub nonce: u64,
}

impl RecursiveProofJob {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: ProofJobKind,
        payload_ids: Vec<String>,
        parent_job_ids: Vec<String>,
        prover_commitment: &str,
        input_root: &str,
        witness_root: &str,
        proof_root: &str,
        recursion_depth: u64,
        target_pq_security_bits: u16,
        max_fee_micro_units: u64,
        sponsor_voucher_id: Option<String>,
        created_height: u64,
        expires_height: u64,
        status: ProofJobStatus,
        nonce: u64,
    ) -> Self {
        let job_id = proof_job_id(
            kind,
            &payload_ids,
            &parent_job_ids,
            input_root,
            witness_root,
            created_height,
            nonce,
        );
        Self {
            job_id,
            kind,
            payload_ids,
            parent_job_ids,
            prover_commitment: prover_commitment.to_string(),
            input_root: input_root.to_string(),
            witness_root: witness_root.to_string(),
            proof_root: proof_root.to_string(),
            recursion_depth,
            target_pq_security_bits,
            max_fee_micro_units,
            sponsor_voucher_id,
            created_height,
            expires_height,
            status,
            nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "job_id": self.job_id,
            "kind": self.kind.as_str(),
            "payload_ids": self.payload_ids,
            "parent_job_ids": self.parent_job_ids,
            "prover_commitment": self.prover_commitment,
            "input_root": self.input_root,
            "witness_root": self.witness_root,
            "proof_root": self.proof_root,
            "recursion_depth": self.recursion_depth,
            "target_pq_security_bits": self.target_pq_security_bits,
            "max_fee_micro_units": self.max_fee_micro_units,
            "sponsor_voucher_id": self.sponsor_voucher_id,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "nonce": self.nonce,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-PROOF-JOB",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SponsorVoucher {
    pub voucher_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_commitment: String,
    pub lane_id: String,
    pub fee_asset_id: String,
    pub max_cover_micro_units: u64,
    pub claimed_micro_units: u64,
    pub rebate_commitment: String,
    pub anonymous_budget_nullifier: String,
    pub issued_height: u64,
    pub expires_height: u64,
    pub status: VoucherStatus,
    pub nonce: u64,
}

impl SponsorVoucher {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_commitment: &str,
        beneficiary_commitment: &str,
        lane_id: &str,
        fee_asset_id: &str,
        max_cover_micro_units: u64,
        claimed_micro_units: u64,
        rebate_commitment: &str,
        anonymous_budget_nullifier: &str,
        issued_height: u64,
        expires_height: u64,
        status: VoucherStatus,
        nonce: u64,
    ) -> Self {
        let voucher_id = sponsor_voucher_id(
            sponsor_commitment,
            beneficiary_commitment,
            lane_id,
            fee_asset_id,
            anonymous_budget_nullifier,
            issued_height,
            nonce,
        );
        Self {
            voucher_id,
            sponsor_commitment: sponsor_commitment.to_string(),
            beneficiary_commitment: beneficiary_commitment.to_string(),
            lane_id: lane_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            max_cover_micro_units,
            claimed_micro_units,
            rebate_commitment: rebate_commitment.to_string(),
            anonymous_budget_nullifier: anonymous_budget_nullifier.to_string(),
            issued_height,
            expires_height,
            status,
            nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "voucher_id": self.voucher_id,
            "sponsor_commitment": self.sponsor_commitment,
            "beneficiary_commitment": self.beneficiary_commitment,
            "lane_id": self.lane_id,
            "fee_asset_id": self.fee_asset_id,
            "max_cover_micro_units": self.max_cover_micro_units,
            "claimed_micro_units": self.claimed_micro_units,
            "rebate_commitment": self.rebate_commitment,
            "anonymous_budget_nullifier": self.anonymous_budget_nullifier,
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "nonce": self.nonce,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-SPONSOR-VOUCHER",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchCompression {
    pub batch_id: String,
    pub lane_id: String,
    pub payload_ids: Vec<String>,
    pub proof_job_ids: Vec<String>,
    pub codec: CompressionCodec,
    pub uncompressed_bytes: u64,
    pub compressed_bytes: u64,
    pub dictionary_root: String,
    pub compressed_payload_root: String,
    pub recursive_proof_root: String,
    pub privacy_set_id: String,
    pub opened_height: u64,
    pub expires_height: u64,
    pub status: BatchStatus,
    pub nonce: u64,
}

impl BatchCompression {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: &str,
        payload_ids: Vec<String>,
        proof_job_ids: Vec<String>,
        codec: CompressionCodec,
        uncompressed_bytes: u64,
        compressed_bytes: u64,
        dictionary_root: &str,
        compressed_payload_root: &str,
        recursive_proof_root: &str,
        privacy_set_id: &str,
        opened_height: u64,
        expires_height: u64,
        status: BatchStatus,
        nonce: u64,
    ) -> Self {
        let batch_id = compression_batch_id(
            lane_id,
            &payload_ids,
            &proof_job_ids,
            codec,
            compressed_payload_root,
            opened_height,
            nonce,
        );
        Self {
            batch_id,
            lane_id: lane_id.to_string(),
            payload_ids,
            proof_job_ids,
            codec,
            uncompressed_bytes,
            compressed_bytes,
            dictionary_root: dictionary_root.to_string(),
            compressed_payload_root: compressed_payload_root.to_string(),
            recursive_proof_root: recursive_proof_root.to_string(),
            privacy_set_id: privacy_set_id.to_string(),
            opened_height,
            expires_height,
            status,
            nonce,
        }
    }

    pub fn compression_ratio_bps(&self) -> u64 {
        if self.uncompressed_bytes == 0 {
            return 0;
        }
        self.compressed_bytes
            .saturating_mul(PRIVATE_L2_LOW_FEE_RECURSIVE_DA_SETTLEMENT_RUNTIME_MAX_BPS)
            / self.uncompressed_bytes
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "payload_ids": self.payload_ids,
            "proof_job_ids": self.proof_job_ids,
            "codec": self.codec.as_str(),
            "uncompressed_bytes": self.uncompressed_bytes,
            "compressed_bytes": self.compressed_bytes,
            "compression_ratio_bps": self.compression_ratio_bps(),
            "dictionary_root": self.dictionary_root,
            "compressed_payload_root": self.compressed_payload_root,
            "recursive_proof_root": self.recursive_proof_root,
            "privacy_set_id": self.privacy_set_id,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "nonce": self.nonce,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-COMPRESSION-BATCH",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub lane_id: String,
    pub settlement_root: String,
    pub proof_root: String,
    pub da_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub user_fee_micro_units: u64,
    pub sponsor_fee_micro_units: u64,
    pub rebate_micro_units: u64,
    pub settled_height: u64,
    pub finality_height: u64,
    pub status: ReceiptStatus,
    pub nonce: u64,
}

impl SettlementReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: &str,
        lane_id: &str,
        settlement_root: &str,
        proof_root: &str,
        da_root: &str,
        state_root_before: &str,
        state_root_after: &str,
        user_fee_micro_units: u64,
        sponsor_fee_micro_units: u64,
        rebate_micro_units: u64,
        settled_height: u64,
        finality_height: u64,
        status: ReceiptStatus,
        nonce: u64,
    ) -> Self {
        let receipt_id = settlement_receipt_id(
            batch_id,
            lane_id,
            settlement_root,
            state_root_before,
            state_root_after,
            settled_height,
            nonce,
        );
        Self {
            receipt_id,
            batch_id: batch_id.to_string(),
            lane_id: lane_id.to_string(),
            settlement_root: settlement_root.to_string(),
            proof_root: proof_root.to_string(),
            da_root: da_root.to_string(),
            state_root_before: state_root_before.to_string(),
            state_root_after: state_root_after.to_string(),
            user_fee_micro_units,
            sponsor_fee_micro_units,
            rebate_micro_units,
            settled_height,
            finality_height,
            status,
            nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "settlement_root": self.settlement_root,
            "proof_root": self.proof_root,
            "da_root": self.da_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "user_fee_micro_units": self.user_fee_micro_units,
            "sponsor_fee_micro_units": self.sponsor_fee_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "settled_height": self.settled_height,
            "finality_height": self.finality_height,
            "status": self.status.as_str(),
            "nonce": self.nonce,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-RECEIPT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RebateClaim {
    pub rebate_id: String,
    pub receipt_id: String,
    pub voucher_id: Option<String>,
    pub beneficiary_commitment: String,
    pub asset_id: String,
    pub amount_micro_units: u64,
    pub claim_nullifier: String,
    pub privacy_set_id: String,
    pub accrued_height: u64,
    pub claimable_height: u64,
    pub status: RebateStatus,
    pub nonce: u64,
}

impl RebateClaim {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        receipt_id: &str,
        voucher_id: Option<String>,
        beneficiary_commitment: &str,
        asset_id: &str,
        amount_micro_units: u64,
        claim_nullifier: &str,
        privacy_set_id: &str,
        accrued_height: u64,
        claimable_height: u64,
        status: RebateStatus,
        nonce: u64,
    ) -> Self {
        let rebate_id = rebate_claim_id(
            receipt_id,
            voucher_id.as_deref().unwrap_or("direct"),
            beneficiary_commitment,
            asset_id,
            claim_nullifier,
            accrued_height,
            nonce,
        );
        Self {
            rebate_id,
            receipt_id: receipt_id.to_string(),
            voucher_id,
            beneficiary_commitment: beneficiary_commitment.to_string(),
            asset_id: asset_id.to_string(),
            amount_micro_units,
            claim_nullifier: claim_nullifier.to_string(),
            privacy_set_id: privacy_set_id.to_string(),
            accrued_height,
            claimable_height,
            status,
            nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "voucher_id": self.voucher_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "asset_id": self.asset_id,
            "amount_micro_units": self.amount_micro_units,
            "claim_nullifier": self.claim_nullifier,
            "privacy_set_id": self.privacy_set_id,
            "accrued_height": self.accrued_height,
            "claimable_height": self.claimable_height,
            "status": self.status.as_str(),
            "nonce": self.nonce,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-REBATE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacySet {
    pub privacy_set_id: String,
    pub label: String,
    pub member_root: String,
    pub minimum_size: u64,
    pub current_size: u64,
    pub epoch: u64,
    pub entry_fee_floor_micro_units: u64,
    pub exit_delay_blocks: u64,
    pub pq_membership_root: String,
    pub active: bool,
}

impl PrivacySet {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: &str,
        member_root: &str,
        minimum_size: u64,
        current_size: u64,
        epoch: u64,
        entry_fee_floor_micro_units: u64,
        exit_delay_blocks: u64,
        pq_membership_root: &str,
        active: bool,
    ) -> Self {
        let privacy_set_id = privacy_set_id(label, member_root, epoch);
        Self {
            privacy_set_id,
            label: label.to_string(),
            member_root: member_root.to_string(),
            minimum_size,
            current_size,
            epoch,
            entry_fee_floor_micro_units,
            exit_delay_blocks,
            pq_membership_root: pq_membership_root.to_string(),
            active,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "privacy_set_id": self.privacy_set_id,
            "label": self.label,
            "member_root": self.member_root,
            "minimum_size": self.minimum_size,
            "current_size": self.current_size,
            "epoch": self.epoch,
            "entry_fee_floor_micro_units": self.entry_fee_floor_micro_units,
            "exit_delay_blocks": self.exit_delay_blocks,
            "pq_membership_root": self.pq_membership_root,
            "active": self.active,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-PRIVACY-SET",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NullifierFence {
    pub fence_id: String,
    pub privacy_set_id: String,
    pub nullifier_root: String,
    pub epoch: u64,
    pub lower_bound_commitment: String,
    pub upper_bound_commitment: String,
    pub spent_count: u64,
    pub capacity: u64,
    pub accepting: bool,
}

impl NullifierFence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        privacy_set_id_value: &str,
        nullifier_root: &str,
        epoch: u64,
        lower_bound_commitment: &str,
        upper_bound_commitment: &str,
        spent_count: u64,
        capacity: u64,
        accepting: bool,
    ) -> Self {
        let fence_id = nullifier_fence_id(
            privacy_set_id_value,
            nullifier_root,
            lower_bound_commitment,
            upper_bound_commitment,
            epoch,
        );
        Self {
            fence_id,
            privacy_set_id: privacy_set_id_value.to_string(),
            nullifier_root: nullifier_root.to_string(),
            epoch,
            lower_bound_commitment: lower_bound_commitment.to_string(),
            upper_bound_commitment: upper_bound_commitment.to_string(),
            spent_count,
            capacity,
            accepting,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "privacy_set_id": self.privacy_set_id,
            "nullifier_root": self.nullifier_root,
            "epoch": self.epoch,
            "lower_bound_commitment": self.lower_bound_commitment,
            "upper_bound_commitment": self.upper_bound_commitment,
            "spent_count": self.spent_count,
            "capacity": self.capacity,
            "accepting": self.accepting,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-NULLIFIER-FENCE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub da_lanes: BTreeMap<String, DaSettlementLane>,
    pub payloads: BTreeMap<String, DaPayload>,
    pub proof_jobs: BTreeMap<String, RecursiveProofJob>,
    pub sponsor_vouchers: BTreeMap<String, SponsorVoucher>,
    pub compression_batches: BTreeMap<String, BatchCompression>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, RebateClaim>,
    pub privacy_sets: BTreeMap<String, PrivacySet>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub seen_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            counters: Counters::default(),
            da_lanes: BTreeMap::new(),
            payloads: BTreeMap::new(),
            proof_jobs: BTreeMap::new(),
            sponsor_vouchers: BTreeMap::new(),
            compression_batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_sets: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            seen_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::default());
        let height = PRIVATE_L2_LOW_FEE_RECURSIVE_DA_SETTLEMENT_RUNTIME_DEVNET_HEIGHT;
        let privacy_fast = PrivacySet::new(
            "devnet-fast-low-fee-da",
            &sample_root("privacy-members-fast", 0),
            DEFAULT_MIN_PRIVACY_SET_SIZE,
            98_304,
            7,
            2,
            18,
            &sample_root("pq-members-fast", 0),
            true,
        );
        let privacy_defi = PrivacySet::new(
            "devnet-defi-da-netting",
            &sample_root("privacy-members-defi", 1),
            DEFAULT_MIN_PRIVACY_SET_SIZE,
            147_456,
            7,
            3,
            20,
            &sample_root("pq-members-defi", 1),
            true,
        );
        let fence_fast = NullifierFence::new(
            &privacy_fast.privacy_set_id,
            &sample_root("nullifiers-fast", 0),
            7,
            &sample_root("nullifier-low-fast", 0),
            &sample_root("nullifier-high-fast", 0),
            42,
            262_144,
            true,
        );
        let fence_defi = NullifierFence::new(
            &privacy_defi.privacy_set_id,
            &sample_root("nullifiers-defi", 1),
            7,
            &sample_root("nullifier-low-defi", 1),
            &sample_root("nullifier-high-defi", 1),
            61,
            262_144,
            true,
        );
        state.insert_privacy_set(privacy_fast.clone());
        state.insert_privacy_set(privacy_defi.clone());
        state.insert_nullifier_fence(fence_fast.clone());
        state.insert_nullifier_fence(fence_defi.clone());

        let lane_fast = DaSettlementLane::new(
            DaLaneKind::EncryptedWitness,
            LaneStatus::Sponsored,
            "operator:devnet:low-fee-fast",
            "asset:xmr-fee-credit",
            96_000,
            18,
            "sponsor-pool:devnet-fast",
            &privacy_fast.privacy_set_id,
            &sample_root("availability-quorum-fast", 0),
            &sample_root("recursive-verifier-fast", 0),
            height - 512,
            1,
        );
        let lane_defi = DaSettlementLane::new(
            DaLaneKind::DefiNetting,
            LaneStatus::Open,
            "operator:devnet:defi-netting",
            "asset:private-usd",
            192_000,
            22,
            "sponsor-pool:devnet-defi",
            &privacy_defi.privacy_set_id,
            &sample_root("availability-quorum-defi", 1),
            &sample_root("recursive-verifier-defi", 1),
            height - 448,
            2,
        );
        state.insert_lane(lane_fast.clone());
        state.insert_lane(lane_defi.clone());

        let payload_fast = DaPayload::new(
            &lane_fast.lane_id,
            "submitter:commitment:fast-wallet-01",
            &sample_root("payload-commitment-fast", 0),
            &sample_root("encrypted-payload-fast", 0),
            &sample_root("erasure-fast", 0),
            &sample_root("public-inputs-fast", 0),
            42_240,
            14,
            &privacy_fast.privacy_set_id,
            &fence_fast.fence_id,
            height - 6,
            height + DEFAULT_JOB_TTL_BLOCKS,
            PayloadStatus::Compressed,
            11,
        );
        let payload_defi = DaPayload::new(
            &lane_defi.lane_id,
            "submitter:commitment:defi-solver-02",
            &sample_root("payload-commitment-defi", 1),
            &sample_root("encrypted-payload-defi", 1),
            &sample_root("erasure-defi", 1),
            &sample_root("public-inputs-defi", 1),
            86_016,
            19,
            &privacy_defi.privacy_set_id,
            &fence_defi.fence_id,
            height - 5,
            height + DEFAULT_JOB_TTL_BLOCKS,
            PayloadStatus::Compressed,
            12,
        );
        state.insert_payload(payload_fast.clone());
        state.insert_payload(payload_defi.clone());

        let voucher_fast = SponsorVoucher::new(
            "sponsor:devnet:latency-maker",
            &payload_fast.submitter_commitment,
            &lane_fast.lane_id,
            &lane_fast.fee_asset_id,
            15,
            11,
            &sample_root("rebate-fast", 0),
            &sample_root("budget-nullifier-fast", 0),
            height - 7,
            height + DEFAULT_VOUCHER_TTL_BLOCKS,
            VoucherStatus::Claimed,
            21,
        );
        let voucher_defi = SponsorVoucher::new(
            "sponsor:devnet:defi-depth",
            &payload_defi.submitter_commitment,
            &lane_defi.lane_id,
            &lane_defi.fee_asset_id,
            20,
            16,
            &sample_root("rebate-defi", 1),
            &sample_root("budget-nullifier-defi", 1),
            height - 6,
            height + DEFAULT_VOUCHER_TTL_BLOCKS,
            VoucherStatus::Claimed,
            22,
        );
        state.insert_voucher(voucher_fast.clone());
        state.insert_voucher(voucher_defi.clone());

        let job_fast = RecursiveProofJob::new(
            ProofJobKind::DaInclusion,
            vec![payload_fast.payload_id.clone()],
            Vec::new(),
            "prover:devnet:recursive-a",
            &payload_fast.public_inputs_root,
            &payload_fast.encrypted_payload_root,
            &sample_root("proof-fast", 0),
            2,
            DEFAULT_MIN_PQ_SECURITY_BITS,
            17,
            Some(voucher_fast.voucher_id.clone()),
            height - 4,
            height + DEFAULT_JOB_TTL_BLOCKS,
            ProofJobStatus::Aggregated,
            31,
        );
        let job_defi = RecursiveProofJob::new(
            ProofJobKind::DefiNetting,
            vec![payload_defi.payload_id.clone()],
            vec![job_fast.job_id.clone()],
            "prover:devnet:recursive-b",
            &payload_defi.public_inputs_root,
            &payload_defi.encrypted_payload_root,
            &sample_root("proof-defi", 1),
            3,
            DEFAULT_MIN_PQ_SECURITY_BITS,
            21,
            Some(voucher_defi.voucher_id.clone()),
            height - 3,
            height + DEFAULT_JOB_TTL_BLOCKS,
            ProofJobStatus::Aggregated,
            32,
        );
        state.insert_proof_job(job_fast.clone());
        state.insert_proof_job(job_defi.clone());

        let batch = BatchCompression::new(
            &lane_defi.lane_id,
            vec![
                payload_fast.payload_id.clone(),
                payload_defi.payload_id.clone(),
            ],
            vec![job_fast.job_id.clone(), job_defi.job_id.clone()],
            CompressionCodec::RecursiveTranscript,
            payload_fast.data_bytes + payload_defi.data_bytes,
            39_744,
            &sample_root("dictionary-devnet", 0),
            &sample_root("compressed-payload-devnet", 0),
            &sample_root("recursive-proof-devnet", 0),
            &privacy_defi.privacy_set_id,
            height - 2,
            height + DEFAULT_BATCH_TTL_BLOCKS,
            BatchStatus::Settled,
            41,
        );
        state.insert_compression_batch(batch.clone());

        let before_root = sample_root("state-before", 0);
        let after_root = sample_root("state-after", 0);
        let receipt = SettlementReceipt::new(
            &batch.batch_id,
            &batch.lane_id,
            &root_from_record("DEVNET-SETTLEMENT-PAYLOAD", &batch.public_record()),
            &batch.recursive_proof_root,
            &batch.compressed_payload_root,
            &before_root,
            &after_root,
            5,
            27,
            3,
            height,
            height + 8,
            ReceiptStatus::Finalized,
            51,
        );
        state.insert_receipt(receipt.clone());

        let rebate_fast = RebateClaim::new(
            &receipt.receipt_id,
            Some(voucher_fast.voucher_id.clone()),
            &payload_fast.submitter_commitment,
            &lane_fast.fee_asset_id,
            1,
            &sample_root("claim-nullifier-fast", 0),
            &privacy_fast.privacy_set_id,
            height,
            height + 2,
            RebateStatus::Claimable,
            61,
        );
        let rebate_defi = RebateClaim::new(
            &receipt.receipt_id,
            Some(voucher_defi.voucher_id.clone()),
            &payload_defi.submitter_commitment,
            &lane_defi.fee_asset_id,
            2,
            &sample_root("claim-nullifier-defi", 1),
            &privacy_defi.privacy_set_id,
            height,
            height + 2,
            RebateStatus::Claimable,
            62,
        );
        state.insert_rebate(rebate_fast);
        state.insert_rebate(rebate_defi);
        state.refresh_counters();
        state.refresh_public_records();
        state
    }

    pub fn insert_lane(&mut self, lane: DaSettlementLane) {
        self.public_records
            .insert(format!("lane:{}", lane.lane_id), lane.public_record());
        self.da_lanes.insert(lane.lane_id.clone(), lane);
    }

    pub fn insert_payload(&mut self, payload: DaPayload) {
        self.counters.payloads_submitted = self.counters.payloads_submitted.saturating_add(1);
        self.counters.payload_bytes = self
            .counters
            .payload_bytes
            .saturating_add(payload.data_bytes);
        self.public_records.insert(
            format!("payload:{}", payload.payload_id),
            payload.public_record(),
        );
        self.payloads.insert(payload.payload_id.clone(), payload);
    }

    pub fn insert_proof_job(&mut self, job: RecursiveProofJob) {
        self.counters.proof_jobs_created = self.counters.proof_jobs_created.saturating_add(1);
        if matches!(job.status, ProofJobStatus::Settled) {
            self.counters.proof_jobs_settled = self.counters.proof_jobs_settled.saturating_add(1);
        }
        self.public_records
            .insert(format!("proof_job:{}", job.job_id), job.public_record());
        self.proof_jobs.insert(job.job_id.clone(), job);
    }

    pub fn insert_voucher(&mut self, voucher: SponsorVoucher) {
        self.counters.vouchers_issued = self.counters.vouchers_issued.saturating_add(1);
        if matches!(
            voucher.status,
            VoucherStatus::Claimed | VoucherStatus::Settled | VoucherStatus::Rebated
        ) {
            self.counters.vouchers_claimed = self.counters.vouchers_claimed.saturating_add(1);
        }
        self.counters.sponsor_fee_micro_units = self
            .counters
            .sponsor_fee_micro_units
            .saturating_add(voucher.claimed_micro_units);
        self.seen_nullifiers
            .insert(voucher.anonymous_budget_nullifier.clone());
        self.public_records.insert(
            format!("voucher:{}", voucher.voucher_id),
            voucher.public_record(),
        );
        self.sponsor_vouchers
            .insert(voucher.voucher_id.clone(), voucher);
    }

    pub fn insert_compression_batch(&mut self, batch: BatchCompression) {
        self.counters.compression_batches = self.counters.compression_batches.saturating_add(1);
        self.counters.compressed_bytes = self
            .counters
            .compressed_bytes
            .saturating_add(batch.compressed_bytes);
        self.public_records
            .insert(format!("batch:{}", batch.batch_id), batch.public_record());
        self.compression_batches
            .insert(batch.batch_id.clone(), batch);
    }

    pub fn insert_receipt(&mut self, receipt: SettlementReceipt) {
        self.counters.settlement_receipts = self.counters.settlement_receipts.saturating_add(1);
        self.counters.user_fee_micro_units = self
            .counters
            .user_fee_micro_units
            .saturating_add(receipt.user_fee_micro_units);
        self.counters.sponsor_fee_micro_units = self
            .counters
            .sponsor_fee_micro_units
            .saturating_add(receipt.sponsor_fee_micro_units);
        self.counters.rebate_micro_units = self
            .counters
            .rebate_micro_units
            .saturating_add(receipt.rebate_micro_units);
        self.public_records.insert(
            format!("receipt:{}", receipt.receipt_id),
            receipt.public_record(),
        );
        self.settlement_receipts
            .insert(receipt.receipt_id.clone(), receipt);
    }

    pub fn insert_rebate(&mut self, rebate: RebateClaim) {
        self.counters.rebates_accrued = self.counters.rebates_accrued.saturating_add(1);
        if matches!(rebate.status, RebateStatus::Paid) {
            self.counters.rebates_paid = self.counters.rebates_paid.saturating_add(1);
        }
        self.seen_nullifiers.insert(rebate.claim_nullifier.clone());
        self.public_records.insert(
            format!("rebate:{}", rebate.rebate_id),
            rebate.public_record(),
        );
        self.rebates.insert(rebate.rebate_id.clone(), rebate);
    }

    pub fn insert_privacy_set(&mut self, privacy_set: PrivacySet) {
        self.public_records.insert(
            format!("privacy_set:{}", privacy_set.privacy_set_id),
            privacy_set.public_record(),
        );
        self.privacy_sets
            .insert(privacy_set.privacy_set_id.clone(), privacy_set);
    }

    pub fn insert_nullifier_fence(&mut self, fence: NullifierFence) {
        self.public_records.insert(
            format!("nullifier_fence:{}", fence.fence_id),
            fence.public_record(),
        );
        self.nullifier_fences.insert(fence.fence_id.clone(), fence);
    }

    pub fn record_nullifier(&mut self, nullifier: &str) -> bool {
        if !self.seen_nullifiers.insert(nullifier.to_string()) {
            self.counters.nullifier_fence_hits =
                self.counters.nullifier_fence_hits.saturating_add(1);
            return false;
        }
        true
    }

    pub fn refresh_counters(&mut self) {
        self.counters.payloads_submitted = self.payloads.len() as u64;
        self.counters.payload_bytes = self
            .payloads
            .values()
            .map(|payload| payload.data_bytes)
            .sum();
        self.counters.proof_jobs_created = self.proof_jobs.len() as u64;
        self.counters.proof_jobs_settled = self
            .proof_jobs
            .values()
            .filter(|job| matches!(job.status, ProofJobStatus::Settled))
            .count() as u64;
        self.counters.vouchers_issued = self.sponsor_vouchers.len() as u64;
        self.counters.vouchers_claimed = self
            .sponsor_vouchers
            .values()
            .filter(|voucher| {
                matches!(
                    voucher.status,
                    VoucherStatus::Claimed | VoucherStatus::Settled | VoucherStatus::Rebated
                )
            })
            .count() as u64;
        self.counters.compression_batches = self.compression_batches.len() as u64;
        self.counters.compressed_bytes = self
            .compression_batches
            .values()
            .map(|batch| batch.compressed_bytes)
            .sum();
        self.counters.settlement_receipts = self.settlement_receipts.len() as u64;
        self.counters.rebates_accrued = self.rebates.len() as u64;
        self.counters.rebates_paid = self
            .rebates
            .values()
            .filter(|rebate| matches!(rebate.status, RebateStatus::Paid))
            .count() as u64;
        self.counters.user_fee_micro_units = self
            .settlement_receipts
            .values()
            .map(|receipt| receipt.user_fee_micro_units)
            .sum();
        self.counters.sponsor_fee_micro_units = self
            .settlement_receipts
            .values()
            .map(|receipt| receipt.sponsor_fee_micro_units)
            .sum();
        self.counters.rebate_micro_units = self
            .settlement_receipts
            .values()
            .map(|receipt| receipt.rebate_micro_units)
            .sum();
        self.counters.privacy_set_merges = self
            .privacy_sets
            .values()
            .filter(|set| set.current_size >= set.minimum_size)
            .count() as u64;
    }

    pub fn refresh_public_records(&mut self) {
        self.public_records.clear();
        self.public_records
            .insert("config".to_string(), self.config.public_record());
        self.public_records
            .insert("counters".to_string(), self.counters.public_record());
        for lane in self.da_lanes.values() {
            self.public_records
                .insert(format!("lane:{}", lane.lane_id), lane.public_record());
        }
        for payload in self.payloads.values() {
            self.public_records.insert(
                format!("payload:{}", payload.payload_id),
                payload.public_record(),
            );
        }
        for job in self.proof_jobs.values() {
            self.public_records
                .insert(format!("proof_job:{}", job.job_id), job.public_record());
        }
        for voucher in self.sponsor_vouchers.values() {
            self.public_records.insert(
                format!("voucher:{}", voucher.voucher_id),
                voucher.public_record(),
            );
        }
        for batch in self.compression_batches.values() {
            self.public_records
                .insert(format!("batch:{}", batch.batch_id), batch.public_record());
        }
        for receipt in self.settlement_receipts.values() {
            self.public_records.insert(
                format!("receipt:{}", receipt.receipt_id),
                receipt.public_record(),
            );
        }
        for rebate in self.rebates.values() {
            self.public_records.insert(
                format!("rebate:{}", rebate.rebate_id),
                rebate.public_record(),
            );
        }
        for privacy_set in self.privacy_sets.values() {
            self.public_records.insert(
                format!("privacy_set:{}", privacy_set.privacy_set_id),
                privacy_set.public_record(),
            );
        }
        for fence in self.nullifier_fences.values() {
            self.public_records.insert(
                format!("nullifier_fence:{}", fence.fence_id),
                fence.public_record(),
            );
        }
    }

    pub fn roots(&self) -> Roots {
        let public_root = self.public_record_root();
        let mut roots = Roots {
            config_root: self.config.root(),
            lane_root: map_values_root(
                "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-LANES",
                &self.da_lanes,
            ),
            payload_root: map_values_root(
                "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-PAYLOADS",
                &self.payloads,
            ),
            proof_job_root: map_values_root(
                "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-PROOF-JOBS",
                &self.proof_jobs,
            ),
            voucher_root: map_values_root(
                "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-VOUCHERS",
                &self.sponsor_vouchers,
            ),
            compression_batch_root: map_values_root(
                "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-BATCHES",
                &self.compression_batches,
            ),
            receipt_root: map_values_root(
                "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-RECEIPTS",
                &self.settlement_receipts,
            ),
            rebate_root: map_values_root(
                "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-REBATES",
                &self.rebates,
            ),
            privacy_set_root: map_values_root(
                "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-PRIVACY-SETS",
                &self.privacy_sets,
            ),
            nullifier_fence_root: map_values_root(
                "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-NULLIFIER-FENCES",
                &self.nullifier_fences,
            ),
            public_record_root: public_root,
            counters_root: self.counters.root(),
            state_root: String::new(),
        };
        roots.state_root = state_root_from_record(&json!({
            "config_root": roots.config_root,
            "lane_root": roots.lane_root,
            "payload_root": roots.payload_root,
            "proof_job_root": roots.proof_job_root,
            "voucher_root": roots.voucher_root,
            "compression_batch_root": roots.compression_batch_root,
            "receipt_root": roots.receipt_root,
            "rebate_root": roots.rebate_root,
            "privacy_set_root": roots.privacy_set_root,
            "nullifier_fence_root": roots.nullifier_fence_root,
            "public_record_root": roots.public_record_root,
            "counters_root": roots.counters_root,
        }));
        roots
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_LOW_FEE_RECURSIVE_DA_SETTLEMENT_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_LOW_FEE_RECURSIVE_DA_SETTLEMENT_RUNTIME_SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "da_lanes": self.da_lanes.values().map(DaSettlementLane::public_record).collect::<Vec<_>>(),
            "payloads": self.payloads.values().map(DaPayload::public_record).collect::<Vec<_>>(),
            "proof_jobs": self.proof_jobs.values().map(RecursiveProofJob::public_record).collect::<Vec<_>>(),
            "sponsor_vouchers": self.sponsor_vouchers.values().map(SponsorVoucher::public_record).collect::<Vec<_>>(),
            "compression_batches": self.compression_batches.values().map(BatchCompression::public_record).collect::<Vec<_>>(),
            "settlement_receipts": self.settlement_receipts.values().map(SettlementReceipt::public_record).collect::<Vec<_>>(),
            "rebates": self.rebates.values().map(RebateClaim::public_record).collect::<Vec<_>>(),
            "privacy_sets": self.privacy_sets.values().map(PrivacySet::public_record).collect::<Vec<_>>(),
            "nullifier_fences": self.nullifier_fences.values().map(NullifierFence::public_record).collect::<Vec<_>>(),
            "seen_nullifier_root": self.seen_nullifier_root(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record["state_root"] = json!(self.state_root());
        record
    }

    pub fn public_record_root(&self) -> String {
        let leaves = self.public_records.values().cloned().collect::<Vec<_>>();
        public_record_root(&leaves)
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_root())
    }

    pub fn seen_nullifier_root(&self) -> String {
        let leaves = self
            .seen_nullifiers
            .iter()
            .map(|value| json!(value))
            .collect::<Vec<_>>();
        merkle_root(
            "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-SEEN-NULLIFIERS",
            &leaves,
        )
    }
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for DaSettlementLane {
    fn public_record(&self) -> Value {
        DaSettlementLane::public_record(self)
    }
}

impl PublicRecord for DaPayload {
    fn public_record(&self) -> Value {
        DaPayload::public_record(self)
    }
}

impl PublicRecord for RecursiveProofJob {
    fn public_record(&self) -> Value {
        RecursiveProofJob::public_record(self)
    }
}

impl PublicRecord for SponsorVoucher {
    fn public_record(&self) -> Value {
        SponsorVoucher::public_record(self)
    }
}

impl PublicRecord for BatchCompression {
    fn public_record(&self) -> Value {
        BatchCompression::public_record(self)
    }
}

impl PublicRecord for SettlementReceipt {
    fn public_record(&self) -> Value {
        SettlementReceipt::public_record(self)
    }
}

impl PublicRecord for RebateClaim {
    fn public_record(&self) -> Value {
        RebateClaim::public_record(self)
    }
}

impl PublicRecord for PrivacySet {
    fn public_record(&self) -> Value {
        PrivacySet::public_record(self)
    }
}

impl PublicRecord for NullifierFence {
    fn public_record(&self) -> Value {
        NullifierFence::public_record(self)
    }
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn public_record_root(records: &[Value]) -> String {
    merkle_root(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-PUBLIC-RECORDS",
        records,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-STATE",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn lane_id(
    kind: DaLaneKind,
    operator_commitment: &str,
    fee_asset_id: &str,
    privacy_set_id: &str,
    opened_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(operator_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Str(privacy_set_id),
            HashPart::Int(opened_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn da_payload_id(
    lane_id_value: &str,
    submitter_commitment: &str,
    payload_commitment: &str,
    encrypted_payload_root: &str,
    submitted_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-PAYLOAD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id_value),
            HashPart::Str(submitter_commitment),
            HashPart::Str(payload_commitment),
            HashPart::Str(encrypted_payload_root),
            HashPart::Int(submitted_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn proof_job_id(
    kind: ProofJobKind,
    payload_ids: &[String],
    parent_job_ids: &[String],
    input_root: &str,
    witness_root: &str,
    created_height: u64,
    nonce: u64,
) -> String {
    let payload_record = json!({"payload_ids": payload_ids, "parent_job_ids": parent_job_ids});
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-PROOF-JOB-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Json(&payload_record),
            HashPart::Str(input_root),
            HashPart::Str(witness_root),
            HashPart::Int(created_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn sponsor_voucher_id(
    sponsor_commitment: &str,
    beneficiary_commitment: &str,
    lane_id_value: &str,
    fee_asset_id: &str,
    anonymous_budget_nullifier: &str,
    issued_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-SPONSOR-VOUCHER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(lane_id_value),
            HashPart::Str(fee_asset_id),
            HashPart::Str(anonymous_budget_nullifier),
            HashPart::Int(issued_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn compression_batch_id(
    lane_id_value: &str,
    payload_ids: &[String],
    proof_job_ids: &[String],
    codec: CompressionCodec,
    compressed_payload_root: &str,
    opened_height: u64,
    nonce: u64,
) -> String {
    let batch_record = json!({"payload_ids": payload_ids, "proof_job_ids": proof_job_ids});
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-COMPRESSION-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id_value),
            HashPart::Json(&batch_record),
            HashPart::Str(codec.as_str()),
            HashPart::Str(compressed_payload_root),
            HashPart::Int(opened_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn settlement_receipt_id(
    batch_id: &str,
    lane_id_value: &str,
    settlement_root: &str,
    state_root_before: &str,
    state_root_after: &str,
    settled_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(lane_id_value),
            HashPart::Str(settlement_root),
            HashPart::Str(state_root_before),
            HashPart::Str(state_root_after),
            HashPart::Int(settled_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn rebate_claim_id(
    receipt_id: &str,
    voucher_id: &str,
    beneficiary_commitment: &str,
    asset_id: &str,
    claim_nullifier: &str,
    accrued_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(voucher_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(asset_id),
            HashPart::Str(claim_nullifier),
            HashPart::Int(accrued_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn privacy_set_id(label: &str, member_root: &str, epoch: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-PRIVACY-SET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(member_root),
            HashPart::Int(epoch as i128),
        ],
        32,
    )
}

pub fn nullifier_fence_id(
    privacy_set_id_value: &str,
    nullifier_root: &str,
    lower_bound_commitment: &str,
    upper_bound_commitment: &str,
    epoch: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-NULLIFIER-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(privacy_set_id_value),
            HashPart::Str(nullifier_root),
            HashPart::Str(lower_bound_commitment),
            HashPart::Str(upper_bound_commitment),
            HashPart::Int(epoch as i128),
        ],
        32,
    )
}

pub fn sample_root(label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-DA-SETTLEMENT-DEVNET-SAMPLE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

fn map_values_root<T: PublicRecord>(domain: &str, values: &BTreeMap<String, T>) -> String {
    let leaves = values
        .values()
        .map(PublicRecord::public_record)
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn ensure_non_empty(
    label: &str,
    value: &str,
) -> PrivateL2LowFeeRecursiveDaSettlementRuntimeResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must be non-empty"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(
    label: &str,
    value: usize,
) -> PrivateL2LowFeeRecursiveDaSettlementRuntimeResult<()> {
    if value == 0 {
        Err(format!("{label} must be non-zero"))
    } else {
        Ok(())
    }
}

fn ensure_bps(label: &str, value: u64) -> PrivateL2LowFeeRecursiveDaSettlementRuntimeResult<()> {
    if value > PRIVATE_L2_LOW_FEE_RECURSIVE_DA_SETTLEMENT_RUNTIME_MAX_BPS {
        Err(format!("{label} exceeds bps denominator"))
    } else {
        Ok(())
    }
}
