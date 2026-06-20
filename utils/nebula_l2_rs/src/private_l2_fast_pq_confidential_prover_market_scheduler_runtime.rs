use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialProverMarketSchedulerRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PROVER_MARKET_SCHEDULER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-prover-market-scheduler-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PROVER_MARKET_SCHEDULER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 2_640_000;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-prover-scheduler-v1";
pub const ENCRYPTED_JOB_METADATA_SCHEME: &str = "ml-kem-sealed-proof-job-metadata-root-v1";
pub const PROVER_RESERVATION_SCHEME: &str = "fast-pq-confidential-prover-reservation-root-v1";
pub const PROOF_JOB_AUCTION_SCHEME: &str = "sealed-confidential-proof-job-auction-root-v1";
pub const ACCELERATOR_LANE_SCHEME: &str = "pq-confidential-accelerator-lane-root-v1";
pub const RECURSIVE_AGGREGATION_QUEUE_SCHEME: &str = "fast-pq-recursive-aggregation-queue-root-v1";
pub const WITNESS_AVAILABILITY_HINT_SCHEME: &str =
    "confidential-state-witness-availability-hint-root-v1";
pub const LATENCY_QOS_SCHEME: &str = "private-l2-fast-proof-latency-qos-root-v1";
pub const VERIFIER_RECEIPT_SCHEME: &str = "pq-confidential-scheduler-verifier-receipt-root-v1";
pub const LOW_FEE_REBATE_SCHEME: &str = "confidential-prover-market-low-fee-rebate-root-v1";
pub const PRIVACY_FENCE_SCHEME: &str = "nullifier-viewtag-confidential-prover-fence-root-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str =
    "pq-confidential-prover-market-slashing-evidence-root-v1";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_LATENCY_MS: u64 = 900;
pub const DEFAULT_HARD_LATENCY_MS: u64 = 2_400;
pub const DEFAULT_AUCTION_TTL_BLOCKS: u64 = 8;
pub const DEFAULT_JOB_TTL_BLOCKS: u64 = 16;
pub const DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 6;
pub const DEFAULT_ACCELERATOR_EPOCH_BLOCKS: u64 = 32;
pub const DEFAULT_AGGREGATION_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_WITNESS_HINT_TTL_BLOCKS: u64 = 10;
pub const DEFAULT_METADATA_TTL_BLOCKS: u64 = 20;
pub const DEFAULT_QOS_EPOCH_BLOCKS: u64 = 32;
pub const DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 6;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_FENCE_TTL_BLOCKS: u64 = 512;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 64;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 10;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 6;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_500;
pub const DEFAULT_MIN_PROVER_BOND_PICONERO: u64 = 2_000_000_000;
pub const DEFAULT_MAX_AUCTIONS: usize = 4_194_304;
pub const DEFAULT_MAX_JOBS: usize = 4_194_304;
pub const DEFAULT_MAX_RESERVATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_ACCELERATOR_LANES: usize = 1_048_576;
pub const DEFAULT_MAX_AGGREGATION_QUEUES: usize = 1_048_576;
pub const DEFAULT_MAX_WITNESS_HINTS: usize = 8_388_608;
pub const DEFAULT_MAX_METADATA: usize = 4_194_304;
pub const DEFAULT_MAX_QOS: usize = 262_144;
pub const DEFAULT_MAX_RECEIPTS: usize = 4_194_304;
pub const DEFAULT_MAX_REBATES: usize = 4_194_304;
pub const DEFAULT_MAX_FENCES: usize = 8_388_608;
pub const DEFAULT_MAX_SLASHING_EVIDENCE: usize = 1_048_576;

macro_rules! status_enum {
    ($name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text),+
                }
            }
        }
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofWorkloadKind {
    TransferBatch,
    ContractExecution,
    MoneroExit,
    TokenNetting,
    DefiSettlement,
    OracleAttestation,
    GovernanceTally,
    StateDiff,
    EmergencyEscape,
    LowFeeBulk,
}

impl ProofWorkloadKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TransferBatch => "transfer_batch",
            Self::ContractExecution => "contract_execution",
            Self::MoneroExit => "monero_exit",
            Self::TokenNetting => "token_netting",
            Self::DefiSettlement => "defi_settlement",
            Self::OracleAttestation => "oracle_attestation",
            Self::GovernanceTally => "governance_tally",
            Self::StateDiff => "state_diff",
            Self::EmergencyEscape => "emergency_escape",
            Self::LowFeeBulk => "low_fee_bulk",
        }
    }

    pub fn complexity_weight(self) -> u64 {
        match self {
            Self::EmergencyEscape => 1_200,
            Self::DefiSettlement => 1_050,
            Self::ContractExecution => 1_000,
            Self::MoneroExit => 940,
            Self::TokenNetting => 860,
            Self::StateDiff => 780,
            Self::OracleAttestation => 720,
            Self::TransferBatch => 640,
            Self::GovernanceTally => 560,
            Self::LowFeeBulk => 500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceleratorKind {
    CpuBatch,
    GpuStark,
    FpgaHash,
    AsicMsm,
    RecursiveAggregator,
    WitnessStreamer,
    VerifierCommittee,
    EmergencyReserve,
}

impl AcceleratorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CpuBatch => "cpu_batch",
            Self::GpuStark => "gpu_stark",
            Self::FpgaHash => "fpga_hash",
            Self::AsicMsm => "asic_msm",
            Self::RecursiveAggregator => "recursive_aggregator",
            Self::WitnessStreamer => "witness_streamer",
            Self::VerifierCommittee => "verifier_committee",
            Self::EmergencyReserve => "emergency_reserve",
        }
    }

    pub fn latency_discount_bps(self) -> u64 {
        match self {
            Self::AsicMsm => 2_800,
            Self::GpuStark => 2_400,
            Self::FpgaHash => 2_000,
            Self::RecursiveAggregator => 1_800,
            Self::VerifierCommittee => 1_200,
            Self::WitnessStreamer => 1_000,
            Self::CpuBatch => 700,
            Self::EmergencyReserve => 3_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionClearingRule {
    LowestFeeFirst,
    LatencyWeighted,
    BondWeighted,
    PrivacyWeighted,
    EmergencyPriority,
    RebateMaximizing,
}

impl AuctionClearingRule {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowestFeeFirst => "lowest_fee_first",
            Self::LatencyWeighted => "latency_weighted",
            Self::BondWeighted => "bond_weighted",
            Self::PrivacyWeighted => "privacy_weighted",
            Self::EmergencyPriority => "emergency_priority",
            Self::RebateMaximizing => "rebate_maximizing",
        }
    }
}

status_enum!(AuctionStatus {
    Open => "open",
    Sealed => "sealed",
    Clearing => "clearing",
    Cleared => "cleared",
    Cancelled => "cancelled",
    Expired => "expired",
    Challenged => "challenged"
});
status_enum!(ProofJobStatus {
    Submitted => "submitted",
    Auctioning => "auctioning",
    Reserved => "reserved",
    WitnessReady => "witness_ready",
    Proving => "proving",
    Aggregating => "aggregating",
    Verified => "verified",
    Settled => "settled",
    Failed => "failed",
    Expired => "expired",
    Challenged => "challenged"
});
status_enum!(ReservationStatus {
    Offered => "offered",
    Accepted => "accepted",
    Locked => "locked",
    Proving => "proving",
    Released => "released",
    Paid => "paid",
    Slashed => "slashed",
    Expired => "expired"
});
status_enum!(AcceleratorLaneStatus {
    Open => "open",
    Saturated => "saturated",
    Throttled => "throttled",
    Reserved => "reserved",
    Maintenance => "maintenance",
    EmergencyOnly => "emergency_only",
    Closed => "closed"
});
status_enum!(AggregationQueueStatus {
    Open => "open",
    Locked => "locked",
    Proving => "proving",
    Verified => "verified",
    Settled => "settled",
    Rejected => "rejected",
    Expired => "expired"
});
status_enum!(WitnessHintStatus {
    Posted => "posted",
    Bound => "bound",
    Streaming => "streaming",
    Consumed => "consumed",
    Released => "released",
    Slashed => "slashed",
    Expired => "expired"
});
status_enum!(EncryptedMetadataStatus {
    Posted => "posted",
    Bound => "bound",
    Reencrypted => "reencrypted",
    RevealedToProver => "revealed_to_prover",
    Consumed => "consumed",
    Expired => "expired",
    Challenged => "challenged"
});
status_enum!(LatencyQosStatus {
    Open => "open",
    Healthy => "healthy",
    Degraded => "degraded",
    Throttled => "throttled",
    EmergencyOnly => "emergency_only",
    Closed => "closed"
});
status_enum!(VerifierReceiptStatus {
    Published => "published",
    Accepted => "accepted",
    Finalized => "finalized",
    Reorged => "reorged",
    Challenged => "challenged"
});
status_enum!(LowFeeRebateStatus {
    Reserved => "reserved",
    Applied => "applied",
    Settled => "settled",
    Reclaimed => "reclaimed",
    Expired => "expired",
    Challenged => "challenged"
});
status_enum!(PrivacyFenceStatus {
    Active => "active",
    Consumed => "consumed",
    Released => "released",
    Frozen => "frozen",
    Expired => "expired"
});
status_enum!(SlashingEvidenceStatus {
    Filed => "filed",
    Corroborated => "corroborated",
    Accepted => "accepted",
    Rejected => "rejected",
    Paid => "paid",
    Expired => "expired"
});

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingEvidenceKind {
    InvalidProof,
    WithheldWitness,
    LatencyBreach,
    FeeOvercharge,
    BadAggregation,
    PqSignatureFailure,
    PrivacyLeak,
    DoubleReservation,
    ReceiptEquivocation,
}

impl SlashingEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidProof => "invalid_proof",
            Self::WithheldWitness => "withheld_witness",
            Self::LatencyBreach => "latency_breach",
            Self::FeeOvercharge => "fee_overcharge",
            Self::BadAggregation => "bad_aggregation",
            Self::PqSignatureFailure => "pq_signature_failure",
            Self::PrivacyLeak => "privacy_leak",
            Self::DoubleReservation => "double_reservation",
            Self::ReceiptEquivocation => "receipt_equivocation",
        }
    }

    pub fn slash_bps(self) -> u64 {
        match self {
            Self::InvalidProof | Self::PrivacyLeak => 10_000,
            Self::BadAggregation | Self::PqSignatureFailure | Self::ReceiptEquivocation => 8_000,
            Self::WithheldWitness | Self::DoubleReservation => 6_000,
            Self::LatencyBreach => 3_000,
            Self::FeeOvercharge => 2_000,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub encrypted_job_metadata_scheme: String,
    pub prover_reservation_scheme: String,
    pub proof_job_auction_scheme: String,
    pub accelerator_lane_scheme: String,
    pub recursive_aggregation_queue_scheme: String,
    pub witness_availability_hint_scheme: String,
    pub latency_qos_scheme: String,
    pub verifier_receipt_scheme: String,
    pub low_fee_rebate_scheme: String,
    pub privacy_fence_scheme: String,
    pub slashing_evidence_scheme: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_latency_ms: u64,
    pub hard_latency_ms: u64,
    pub auction_ttl_blocks: u64,
    pub job_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub accelerator_epoch_blocks: u64,
    pub aggregation_ttl_blocks: u64,
    pub witness_hint_ttl_blocks: u64,
    pub metadata_ttl_blocks: u64,
    pub qos_epoch_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub fence_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub min_prover_bond_piconero: u64,
    pub max_auctions: usize,
    pub max_jobs: usize,
    pub max_reservations: usize,
    pub max_accelerator_lanes: usize,
    pub max_aggregation_queues: usize,
    pub max_witness_hints: usize,
    pub max_metadata: usize,
    pub max_qos: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_fences: usize,
    pub max_slashing_evidence: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            encrypted_job_metadata_scheme: ENCRYPTED_JOB_METADATA_SCHEME.to_string(),
            prover_reservation_scheme: PROVER_RESERVATION_SCHEME.to_string(),
            proof_job_auction_scheme: PROOF_JOB_AUCTION_SCHEME.to_string(),
            accelerator_lane_scheme: ACCELERATOR_LANE_SCHEME.to_string(),
            recursive_aggregation_queue_scheme: RECURSIVE_AGGREGATION_QUEUE_SCHEME.to_string(),
            witness_availability_hint_scheme: WITNESS_AVAILABILITY_HINT_SCHEME.to_string(),
            latency_qos_scheme: LATENCY_QOS_SCHEME.to_string(),
            verifier_receipt_scheme: VERIFIER_RECEIPT_SCHEME.to_string(),
            low_fee_rebate_scheme: LOW_FEE_REBATE_SCHEME.to_string(),
            privacy_fence_scheme: PRIVACY_FENCE_SCHEME.to_string(),
            slashing_evidence_scheme: SLASHING_EVIDENCE_SCHEME.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_latency_ms: DEFAULT_TARGET_LATENCY_MS,
            hard_latency_ms: DEFAULT_HARD_LATENCY_MS,
            auction_ttl_blocks: DEFAULT_AUCTION_TTL_BLOCKS,
            job_ttl_blocks: DEFAULT_JOB_TTL_BLOCKS,
            reservation_ttl_blocks: DEFAULT_RESERVATION_TTL_BLOCKS,
            accelerator_epoch_blocks: DEFAULT_ACCELERATOR_EPOCH_BLOCKS,
            aggregation_ttl_blocks: DEFAULT_AGGREGATION_TTL_BLOCKS,
            witness_hint_ttl_blocks: DEFAULT_WITNESS_HINT_TTL_BLOCKS,
            metadata_ttl_blocks: DEFAULT_METADATA_TTL_BLOCKS,
            qos_epoch_blocks: DEFAULT_QOS_EPOCH_BLOCKS,
            receipt_finality_blocks: DEFAULT_RECEIPT_FINALITY_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            fence_ttl_blocks: DEFAULT_FENCE_TTL_BLOCKS,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            min_prover_bond_piconero: DEFAULT_MIN_PROVER_BOND_PICONERO,
            max_auctions: DEFAULT_MAX_AUCTIONS,
            max_jobs: DEFAULT_MAX_JOBS,
            max_reservations: DEFAULT_MAX_RESERVATIONS,
            max_accelerator_lanes: DEFAULT_MAX_ACCELERATOR_LANES,
            max_aggregation_queues: DEFAULT_MAX_AGGREGATION_QUEUES,
            max_witness_hints: DEFAULT_MAX_WITNESS_HINTS,
            max_metadata: DEFAULT_MAX_METADATA,
            max_qos: DEFAULT_MAX_QOS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_fences: DEFAULT_MAX_FENCES,
            max_slashing_evidence: DEFAULT_MAX_SLASHING_EVIDENCE,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(format!(
                "unsupported protocol version: {}",
                self.protocol_version
            ));
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err(format!(
                "unsupported schema version: {}",
                self.schema_version
            ));
        }
        if self.chain_id != CHAIN_ID {
            return Err("unexpected chain id".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security floor must be at least 256 bits".to_string());
        }
        if self.min_privacy_set_size < 65_536 {
            return Err("privacy set size below private L2 floor".to_string());
        }
        if self.target_latency_ms == 0 || self.hard_latency_ms < self.target_latency_ms {
            return Err("latency bounds are invalid".to_string());
        }
        if self.max_user_fee_bps > MAX_BPS
            || self.target_rebate_bps > MAX_BPS
            || self.sponsor_cover_bps > MAX_BPS
        {
            return Err("basis point value exceeds MAX_BPS".to_string());
        }
        if self.min_prover_bond_piconero == 0 {
            return Err("minimum prover bond must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_sequence: u64,
    pub auctions_opened: u64,
    pub proof_jobs_submitted: u64,
    pub reservations_made: u64,
    pub accelerator_lanes_opened: u64,
    pub aggregation_queues_opened: u64,
    pub witness_hints_posted: u64,
    pub metadata_records_posted: u64,
    pub qos_epochs_opened: u64,
    pub verifier_receipts_published: u64,
    pub rebates_reserved: u64,
    pub privacy_fences_opened: u64,
    pub slashing_evidence_filed: u64,
    pub active_nullifiers: u64,
    pub total_proof_weight: u64,
    pub total_bid_count: u64,
    pub total_reserved_bond_piconero: u64,
    pub total_quoted_fee_piconero: u64,
    pub total_rebate_piconero: u64,
    pub total_slashed_bond_piconero: u64,
}

impl Counters {
    pub fn new() -> Self {
        Self {
            next_sequence: 1,
            auctions_opened: 0,
            proof_jobs_submitted: 0,
            reservations_made: 0,
            accelerator_lanes_opened: 0,
            aggregation_queues_opened: 0,
            witness_hints_posted: 0,
            metadata_records_posted: 0,
            qos_epochs_opened: 0,
            verifier_receipts_published: 0,
            rebates_reserved: 0,
            privacy_fences_opened: 0,
            slashing_evidence_filed: 0,
            active_nullifiers: 0,
            total_proof_weight: 0,
            total_bid_count: 0,
            total_reserved_bond_piconero: 0,
            total_quoted_fee_piconero: 0,
            total_rebate_piconero: 0,
            total_slashed_bond_piconero: 0,
        }
    }

    pub fn allocate_sequence(&mut self) -> u64 {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        sequence
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-COUNTERS",
            &self.public_record(),
        )
    }
}

impl Default for Counters {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub auction_root: String,
    pub proof_job_root: String,
    pub reservation_root: String,
    pub accelerator_lane_root: String,
    pub aggregation_queue_root: String,
    pub witness_hint_root: String,
    pub encrypted_metadata_root: String,
    pub latency_qos_root: String,
    pub verifier_receipt_root: String,
    pub low_fee_rebate_root: String,
    pub privacy_fence_root: String,
    pub slashing_evidence_root: String,
    pub active_nullifier_root: String,
    pub policy_hint_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofJobAuction {
    pub auction_id: String,
    pub sequence: u64,
    pub workload_kind: ProofWorkloadKind,
    pub status: AuctionStatus,
    pub clearing_rule: AuctionClearingRule,
    pub encrypted_job_metadata_root: String,
    pub bid_commitment_root: String,
    pub reserve_price_piconero: u64,
    pub max_fee_piconero: u64,
    pub min_bond_piconero: u64,
    pub min_privacy_set_size: u64,
    pub target_latency_ms: u64,
    pub hard_latency_ms: u64,
    pub bid_count: u64,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub cleared_reservation_id: Option<String>,
}

impl ProofJobAuction {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-AUCTION",
            &self.public_record(),
        )
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.auction_id.is_empty() {
            return Err("auction_id is empty".to_string());
        }
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("auction privacy set below configured floor".to_string());
        }
        if self.hard_latency_ms < self.target_latency_ms {
            return Err("auction latency bounds are invalid".to_string());
        }
        if self.min_bond_piconero < config.min_prover_bond_piconero {
            return Err("auction bond below configured floor".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofJob {
    pub job_id: String,
    pub sequence: u64,
    pub auction_id: String,
    pub workload_kind: ProofWorkloadKind,
    pub status: ProofJobStatus,
    pub circuit_id: String,
    pub circuit_version: u64,
    pub proof_system: String,
    pub proving_key_root: String,
    pub public_input_root: String,
    pub private_input_commitment: String,
    pub witness_hint_id: Option<String>,
    pub encrypted_metadata_id: Option<String>,
    pub accelerator_lane_id: Option<String>,
    pub aggregation_queue_id: Option<String>,
    pub reservation_id: Option<String>,
    pub expected_proof_weight: u64,
    pub max_fee_piconero: u64,
    pub priority_score: u64,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl ProofJob {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-JOB",
            &self.public_record(),
        )
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.job_id.is_empty() {
            return Err("job_id is empty".to_string());
        }
        if self.auction_id.is_empty() {
            return Err("job auction id is empty".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("job pq security below configured floor".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("job privacy set below configured floor".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err("job expiry must be after submission".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProverReservation {
    pub reservation_id: String,
    pub sequence: u64,
    pub auction_id: String,
    pub job_id: String,
    pub prover_commitment: String,
    pub accelerator_lane_id: Option<String>,
    pub status: ReservationStatus,
    pub bid_commitment: String,
    pub staked_bond_piconero: u64,
    pub quoted_fee_piconero: u64,
    pub promised_latency_ms: u64,
    pub pq_attestation_root: String,
    pub scheduler_signature_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl ProverReservation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-RESERVATION",
            &self.public_record(),
        )
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.reservation_id.is_empty() {
            return Err("reservation_id is empty".to_string());
        }
        if self.staked_bond_piconero < config.min_prover_bond_piconero {
            return Err("reservation bond below configured floor".to_string());
        }
        if self.promised_latency_ms == 0 || self.promised_latency_ms > config.hard_latency_ms {
            return Err("reservation promised latency outside configured bounds".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AcceleratorLane {
    pub lane_id: String,
    pub sequence: u64,
    pub accelerator_kind: AcceleratorKind,
    pub workload_kind: ProofWorkloadKind,
    pub status: AcceleratorLaneStatus,
    pub operator_commitment: String,
    pub hardware_attestation_root: String,
    pub capacity_weight: u64,
    pub reserved_weight: u64,
    pub target_latency_ms: u64,
    pub hard_latency_ms: u64,
    pub congestion_bps: u64,
    pub base_fee_piconero: u64,
    pub epoch_start_height: u64,
    pub epoch_end_height: u64,
}

impl AcceleratorLane {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-ACCELERATOR-LANE",
            &self.public_record(),
        )
    }

    pub fn available_weight(&self) -> u64 {
        self.capacity_weight.saturating_sub(self.reserved_weight)
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.lane_id.is_empty() {
            return Err("accelerator lane id is empty".to_string());
        }
        if self.congestion_bps > MAX_BPS {
            return Err("accelerator congestion exceeds MAX_BPS".to_string());
        }
        if self.hard_latency_ms < self.target_latency_ms
            || self.hard_latency_ms > config.hard_latency_ms.saturating_mul(4)
        {
            return Err("accelerator lane latency bounds are invalid".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecursiveAggregationQueue {
    pub queue_id: String,
    pub sequence: u64,
    pub workload_kind: ProofWorkloadKind,
    pub status: AggregationQueueStatus,
    pub input_job_root: String,
    pub recursive_vk_root: String,
    pub accumulator_root: String,
    pub transcript_root: String,
    pub queue_depth: u64,
    pub max_depth: u64,
    pub target_latency_ms: u64,
    pub base_fee_piconero: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl RecursiveAggregationQueue {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-AGGREGATION-QUEUE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> Result<()> {
        if self.queue_id.is_empty() {
            return Err("aggregation queue id is empty".to_string());
        }
        if self.queue_depth > self.max_depth {
            return Err("aggregation queue depth exceeds max depth".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessAvailabilityHint {
    pub hint_id: String,
    pub sequence: u64,
    pub job_id: String,
    pub status: WitnessHintStatus,
    pub witness_root: String,
    pub encrypted_witness_blob_root: String,
    pub availability_committee_root: String,
    pub locality_hint_root: String,
    pub owner_commitment: String,
    pub byte_size: u64,
    pub privacy_set_size: u64,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
}

impl WitnessAvailabilityHint {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-WITNESS-HINT",
            &self.public_record(),
        )
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.hint_id.is_empty() {
            return Err("witness hint id is empty".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("witness hint privacy set below configured floor".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedJobMetadata {
    pub metadata_id: String,
    pub sequence: u64,
    pub job_id: String,
    pub status: EncryptedMetadataStatus,
    pub kem_ciphertext_root: String,
    pub metadata_ciphertext_root: String,
    pub access_policy_root: String,
    pub job_tag_root: String,
    pub plaintext_size_commitment: u64,
    pub ciphertext_size: u64,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedJobMetadata {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-ENCRYPTED-METADATA",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> Result<()> {
        if self.metadata_id.is_empty() {
            return Err("metadata id is empty".to_string());
        }
        if self.ciphertext_size < self.plaintext_size_commitment {
            return Err("metadata ciphertext size below plaintext commitment".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LatencyQos {
    pub qos_id: String,
    pub sequence: u64,
    pub workload_kind: ProofWorkloadKind,
    pub status: LatencyQosStatus,
    pub capacity_weight: u64,
    pub reserved_weight: u64,
    pub target_latency_ms: u64,
    pub hard_latency_ms: u64,
    pub observed_p50_latency_ms: u64,
    pub observed_p95_latency_ms: u64,
    pub missed_sla_count: u64,
    pub max_fee_bps: u64,
    pub congestion_bps: u64,
    pub epoch_start_height: u64,
    pub epoch_end_height: u64,
}

impl LatencyQos {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-QOS",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> Result<()> {
        if self.qos_id.is_empty() {
            return Err("qos id is empty".to_string());
        }
        if self.max_fee_bps > MAX_BPS || self.congestion_bps > MAX_BPS {
            return Err("qos bps exceeds MAX_BPS".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifierReceipt {
    pub receipt_id: String,
    pub sequence: u64,
    pub job_id: String,
    pub reservation_id: String,
    pub status: VerifierReceiptStatus,
    pub verifier_committee_root: String,
    pub proof_root: String,
    pub public_input_root: String,
    pub acceptance_root: String,
    pub latency_observation_root: String,
    pub verified_at_height: u64,
    pub finalizes_at_height: u64,
}

impl VerifierReceipt {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-VERIFIER-RECEIPT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> Result<()> {
        if self.receipt_id.is_empty() {
            return Err("receipt id is empty".to_string());
        }
        if self.finalizes_at_height <= self.verified_at_height {
            return Err("receipt finality height must be after verification".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub sequence: u64,
    pub job_id: String,
    pub reservation_id: Option<String>,
    pub sponsor_commitment: String,
    pub status: LowFeeRebateStatus,
    pub fee_asset_id: String,
    pub reserved_rebate_piconero: u64,
    pub applied_rebate_piconero: u64,
    pub max_user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-LOW-FEE-REBATE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> Result<()> {
        if self.rebate_id.is_empty() {
            return Err("rebate id is empty".to_string());
        }
        if self.max_user_fee_bps > MAX_BPS || self.sponsor_cover_bps > MAX_BPS {
            return Err("rebate bps exceeds MAX_BPS".to_string());
        }
        if self.applied_rebate_piconero > self.reserved_rebate_piconero {
            return Err("applied rebate exceeds reserved rebate".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub sequence: u64,
    pub job_id: String,
    pub status: PrivacyFenceStatus,
    pub nullifier_root: String,
    pub view_tag_root: String,
    pub decoy_set_root: String,
    pub disclosure_policy_root: String,
    pub min_privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-PRIVACY-FENCE",
            &self.public_record(),
        )
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.fence_id.is_empty() {
            return Err("privacy fence id is empty".to_string());
        }
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("privacy fence below configured privacy floor".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub sequence: u64,
    pub accused_commitment: String,
    pub job_id: Option<String>,
    pub reservation_id: Option<String>,
    pub receipt_id: Option<String>,
    pub status: SlashingEvidenceStatus,
    pub evidence_kind: SlashingEvidenceKind,
    pub evidence_root: String,
    pub reporter_commitment: String,
    pub slash_amount_piconero: u64,
    pub filed_at_height: u64,
    pub expires_at_height: u64,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        record_root(
            "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-SLASHING-EVIDENCE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> Result<()> {
        if self.evidence_id.is_empty() {
            return Err("slashing evidence id is empty".to_string());
        }
        if self.slash_amount_piconero == 0 {
            return Err("slash amount must be positive".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SchedulerPolicyHint {
    pub hint_id: String,
    pub workload_kind: ProofWorkloadKind,
    pub accelerator_kind: AcceleratorKind,
    pub clearing_rule: AuctionClearingRule,
    pub priority_weight: u64,
    pub target_latency_ms: u64,
    pub max_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub domain: String,
}

impl SchedulerPolicyHint {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub auctions: BTreeMap<String, ProofJobAuction>,
    pub proof_jobs: BTreeMap<String, ProofJob>,
    pub reservations: BTreeMap<String, ProverReservation>,
    pub accelerator_lanes: BTreeMap<String, AcceleratorLane>,
    pub aggregation_queues: BTreeMap<String, RecursiveAggregationQueue>,
    pub witness_hints: BTreeMap<String, WitnessAvailabilityHint>,
    pub encrypted_metadata: BTreeMap<String, EncryptedJobMetadata>,
    pub latency_qos: BTreeMap<String, LatencyQos>,
    pub verifier_receipts: BTreeMap<String, VerifierReceipt>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub active_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let counters = Counters::new();
        let mut state = Self {
            roots: empty_roots(&config, &counters),
            config,
            counters,
            auctions: BTreeMap::new(),
            proof_jobs: BTreeMap::new(),
            reservations: BTreeMap::new(),
            accelerator_lanes: BTreeMap::new(),
            aggregation_queues: BTreeMap::new(),
            witness_hints: BTreeMap::new(),
            encrypted_metadata: BTreeMap::new(),
            latency_qos: BTreeMap::new(),
            verifier_receipts: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            active_nullifiers: BTreeSet::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let counters = Counters::new();
        let mut state = Self {
            roots: empty_roots(&config, &counters),
            config,
            counters,
            auctions: BTreeMap::new(),
            proof_jobs: BTreeMap::new(),
            reservations: BTreeMap::new(),
            accelerator_lanes: BTreeMap::new(),
            aggregation_queues: BTreeMap::new(),
            witness_hints: BTreeMap::new(),
            encrypted_metadata: BTreeMap::new(),
            latency_qos: BTreeMap::new(),
            verifier_receipts: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            active_nullifiers: BTreeSet::new(),
        };
        seed_devnet(&mut state);
        state.refresh_roots();
        state
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "state_root": self.state_root()
        })
    }

    pub fn devnet_state_root() -> String {
        Self::devnet().state_root()
    }

    pub fn devnet_public_record() -> Value {
        Self::devnet().public_record()
    }

    pub fn state_root_from_public_record(record: &Value) -> Result<String> {
        record
            .get("roots")
            .and_then(|roots| roots.get("state_root"))
            .and_then(Value::as_str)
            .or_else(|| record.get("state_root").and_then(Value::as_str))
            .map(str::to_string)
            .ok_or_else(|| "missing state root in public record".to_string())
    }

    pub fn refresh_roots(&mut self) {
        self.recompute_counters();
        let public_record_root = merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-PUBLIC-RECORD",
            &[self.public_record_without_state_root()],
        );
        let mut roots = Roots {
            config_root: self.config.root(),
            counter_root: self.counters.root(),
            auction_root: map_root(
                "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-AUCTIONS",
                &self.auctions,
                ProofJobAuction::public_record,
            ),
            proof_job_root: map_root(
                "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-JOBS",
                &self.proof_jobs,
                ProofJob::public_record,
            ),
            reservation_root: map_root(
                "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-RESERVATIONS",
                &self.reservations,
                ProverReservation::public_record,
            ),
            accelerator_lane_root: map_root(
                "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-ACCELERATOR-LANES",
                &self.accelerator_lanes,
                AcceleratorLane::public_record,
            ),
            aggregation_queue_root: map_root(
                "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-AGGREGATION-QUEUES",
                &self.aggregation_queues,
                RecursiveAggregationQueue::public_record,
            ),
            witness_hint_root: map_root(
                "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-WITNESS-HINTS",
                &self.witness_hints,
                WitnessAvailabilityHint::public_record,
            ),
            encrypted_metadata_root: map_root(
                "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-ENCRYPTED-METADATA",
                &self.encrypted_metadata,
                EncryptedJobMetadata::public_record,
            ),
            latency_qos_root: map_root(
                "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-QOS",
                &self.latency_qos,
                LatencyQos::public_record,
            ),
            verifier_receipt_root: map_root(
                "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-RECEIPTS",
                &self.verifier_receipts,
                VerifierReceipt::public_record,
            ),
            low_fee_rebate_root: map_root(
                "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-REBATES",
                &self.low_fee_rebates,
                LowFeeRebate::public_record,
            ),
            privacy_fence_root: map_root(
                "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-FENCES",
                &self.privacy_fences,
                PrivacyFence::public_record,
            ),
            slashing_evidence_root: map_root(
                "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-SLASHING",
                &self.slashing_evidence,
                SlashingEvidence::public_record,
            ),
            active_nullifier_root: set_root(
                "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-NULLIFIERS",
                &self.active_nullifiers,
            ),
            policy_hint_root: policy_hint_root(),
            public_record_root,
            state_root: String::new(),
        };
        roots.state_root = self.compute_state_root_with(&roots);
        self.roots = roots;
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        self.ensure_capacity()?;
        for record in self.auctions.values() {
            record.validate(&self.config)?;
        }
        for record in self.proof_jobs.values() {
            record.validate(&self.config)?;
        }
        for record in self.reservations.values() {
            record.validate(&self.config)?;
        }
        for record in self.accelerator_lanes.values() {
            record.validate(&self.config)?;
        }
        for record in self.aggregation_queues.values() {
            record.validate()?;
        }
        for record in self.witness_hints.values() {
            record.validate(&self.config)?;
        }
        for record in self.encrypted_metadata.values() {
            record.validate()?;
        }
        for record in self.latency_qos.values() {
            record.validate()?;
        }
        for record in self.verifier_receipts.values() {
            record.validate()?;
        }
        for record in self.low_fee_rebates.values() {
            record.validate()?;
        }
        for record in self.privacy_fences.values() {
            record.validate(&self.config)?;
        }
        for record in self.slashing_evidence.values() {
            record.validate()?;
        }
        Ok(())
    }

    pub fn ensure_capacity(&self) -> Result<()> {
        if self.auctions.len() > self.config.max_auctions {
            return Err("auction capacity exceeded".to_string());
        }
        if self.proof_jobs.len() > self.config.max_jobs {
            return Err("proof job capacity exceeded".to_string());
        }
        if self.reservations.len() > self.config.max_reservations {
            return Err("reservation capacity exceeded".to_string());
        }
        if self.accelerator_lanes.len() > self.config.max_accelerator_lanes {
            return Err("accelerator lane capacity exceeded".to_string());
        }
        if self.aggregation_queues.len() > self.config.max_aggregation_queues {
            return Err("aggregation queue capacity exceeded".to_string());
        }
        if self.witness_hints.len() > self.config.max_witness_hints {
            return Err("witness hint capacity exceeded".to_string());
        }
        if self.encrypted_metadata.len() > self.config.max_metadata {
            return Err("encrypted metadata capacity exceeded".to_string());
        }
        if self.latency_qos.len() > self.config.max_qos {
            return Err("qos capacity exceeded".to_string());
        }
        if self.verifier_receipts.len() > self.config.max_receipts {
            return Err("verifier receipt capacity exceeded".to_string());
        }
        if self.low_fee_rebates.len() > self.config.max_rebates {
            return Err("rebate capacity exceeded".to_string());
        }
        if self.privacy_fences.len() > self.config.max_fences {
            return Err("privacy fence capacity exceeded".to_string());
        }
        if self.slashing_evidence.len() > self.config.max_slashing_evidence {
            return Err("slashing evidence capacity exceeded".to_string());
        }
        Ok(())
    }

    pub fn insert_auction(&mut self, record: ProofJobAuction) -> Result<String> {
        record.validate(&self.config)?;
        let id = record.auction_id.clone();
        self.auctions.insert(id.clone(), record);
        self.ensure_capacity()?;
        self.refresh_roots();
        Ok(id)
    }

    pub fn insert_proof_job(&mut self, record: ProofJob) -> Result<String> {
        record.validate(&self.config)?;
        let id = record.job_id.clone();
        self.proof_jobs.insert(id.clone(), record);
        self.ensure_capacity()?;
        self.refresh_roots();
        Ok(id)
    }

    pub fn insert_reservation(&mut self, record: ProverReservation) -> Result<String> {
        record.validate(&self.config)?;
        let id = record.reservation_id.clone();
        self.reservations.insert(id.clone(), record);
        self.ensure_capacity()?;
        self.refresh_roots();
        Ok(id)
    }

    pub fn insert_accelerator_lane(&mut self, record: AcceleratorLane) -> Result<String> {
        record.validate(&self.config)?;
        let id = record.lane_id.clone();
        self.accelerator_lanes.insert(id.clone(), record);
        self.ensure_capacity()?;
        self.refresh_roots();
        Ok(id)
    }

    pub fn insert_aggregation_queue(
        &mut self,
        record: RecursiveAggregationQueue,
    ) -> Result<String> {
        record.validate()?;
        let id = record.queue_id.clone();
        self.aggregation_queues.insert(id.clone(), record);
        self.ensure_capacity()?;
        self.refresh_roots();
        Ok(id)
    }

    pub fn insert_witness_hint(&mut self, record: WitnessAvailabilityHint) -> Result<String> {
        record.validate(&self.config)?;
        let id = record.hint_id.clone();
        self.witness_hints.insert(id.clone(), record);
        self.ensure_capacity()?;
        self.refresh_roots();
        Ok(id)
    }

    pub fn insert_encrypted_metadata(&mut self, record: EncryptedJobMetadata) -> Result<String> {
        record.validate()?;
        let id = record.metadata_id.clone();
        self.encrypted_metadata.insert(id.clone(), record);
        self.ensure_capacity()?;
        self.refresh_roots();
        Ok(id)
    }

    pub fn insert_latency_qos(&mut self, record: LatencyQos) -> Result<String> {
        record.validate()?;
        let id = record.qos_id.clone();
        self.latency_qos.insert(id.clone(), record);
        self.ensure_capacity()?;
        self.refresh_roots();
        Ok(id)
    }

    pub fn insert_verifier_receipt(&mut self, record: VerifierReceipt) -> Result<String> {
        record.validate()?;
        let id = record.receipt_id.clone();
        self.verifier_receipts.insert(id.clone(), record);
        self.ensure_capacity()?;
        self.refresh_roots();
        Ok(id)
    }

    pub fn insert_low_fee_rebate(&mut self, record: LowFeeRebate) -> Result<String> {
        record.validate()?;
        let id = record.rebate_id.clone();
        self.low_fee_rebates.insert(id.clone(), record);
        self.ensure_capacity()?;
        self.refresh_roots();
        Ok(id)
    }

    pub fn insert_privacy_fence(&mut self, record: PrivacyFence) -> Result<String> {
        record.validate(&self.config)?;
        let id = record.fence_id.clone();
        self.privacy_fences.insert(id.clone(), record);
        self.ensure_capacity()?;
        self.refresh_roots();
        Ok(id)
    }

    pub fn insert_slashing_evidence(&mut self, record: SlashingEvidence) -> Result<String> {
        record.validate()?;
        let id = record.evidence_id.clone();
        self.slashing_evidence.insert(id.clone(), record);
        self.ensure_capacity()?;
        self.refresh_roots();
        Ok(id)
    }

    pub fn add_active_nullifier(&mut self, nullifier: String) -> Result<()> {
        if nullifier.is_empty() {
            return Err("nullifier is empty".to_string());
        }
        self.active_nullifiers.insert(nullifier);
        self.ensure_capacity()?;
        self.refresh_roots();
        Ok(())
    }

    fn recompute_counters(&mut self) {
        let next_sequence = self.counters.next_sequence.max(1);
        self.counters = Counters {
            next_sequence,
            auctions_opened: self.auctions.len() as u64,
            proof_jobs_submitted: self.proof_jobs.len() as u64,
            reservations_made: self.reservations.len() as u64,
            accelerator_lanes_opened: self.accelerator_lanes.len() as u64,
            aggregation_queues_opened: self.aggregation_queues.len() as u64,
            witness_hints_posted: self.witness_hints.len() as u64,
            metadata_records_posted: self.encrypted_metadata.len() as u64,
            qos_epochs_opened: self.latency_qos.len() as u64,
            verifier_receipts_published: self.verifier_receipts.len() as u64,
            rebates_reserved: self.low_fee_rebates.len() as u64,
            privacy_fences_opened: self.privacy_fences.len() as u64,
            slashing_evidence_filed: self.slashing_evidence.len() as u64,
            active_nullifiers: self.active_nullifiers.len() as u64,
            total_proof_weight: self
                .proof_jobs
                .values()
                .map(|job| job.expected_proof_weight)
                .sum(),
            total_bid_count: self
                .auctions
                .values()
                .map(|auction| auction.bid_count)
                .sum(),
            total_reserved_bond_piconero: self
                .reservations
                .values()
                .map(|reservation| reservation.staked_bond_piconero)
                .sum(),
            total_quoted_fee_piconero: self
                .reservations
                .values()
                .map(|reservation| reservation.quoted_fee_piconero)
                .sum(),
            total_rebate_piconero: self
                .low_fee_rebates
                .values()
                .map(|rebate| rebate.reserved_rebate_piconero)
                .sum(),
            total_slashed_bond_piconero: self
                .slashing_evidence
                .values()
                .filter(|evidence| evidence.status == SlashingEvidenceStatus::Accepted)
                .map(|evidence| evidence.slash_amount_piconero)
                .sum(),
        };
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config_root": self.config.root(),
            "counter_root": self.counters.root(),
            "roots_without_state": {
                "auction_root": self.roots.auction_root,
                "proof_job_root": self.roots.proof_job_root,
                "reservation_root": self.roots.reservation_root,
                "accelerator_lane_root": self.roots.accelerator_lane_root,
                "aggregation_queue_root": self.roots.aggregation_queue_root,
                "witness_hint_root": self.roots.witness_hint_root,
                "encrypted_metadata_root": self.roots.encrypted_metadata_root,
                "latency_qos_root": self.roots.latency_qos_root,
                "verifier_receipt_root": self.roots.verifier_receipt_root,
                "low_fee_rebate_root": self.roots.low_fee_rebate_root,
                "privacy_fence_root": self.roots.privacy_fence_root,
                "slashing_evidence_root": self.roots.slashing_evidence_root,
                "active_nullifier_root": self.roots.active_nullifier_root,
                "policy_hint_root": self.roots.policy_hint_root
            }
        })
    }

    fn compute_state_root_with(&self, roots: &Roots) -> String {
        domain_hash(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Json(&roots.public_record()),
            ],
            32,
        )
    }
}

pub fn devnet_state_root() -> String {
    State::devnet_state_root()
}

pub fn devnet_public_record() -> Value {
    State::devnet_public_record()
}

pub fn state_root_from_public_record(record: &Value) -> Result<String> {
    State::state_root_from_public_record(record)
}

pub fn auction_id(
    workload_kind: ProofWorkloadKind,
    metadata_root: &str,
    opened_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-AUCTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(workload_kind.as_str()),
            HashPart::Str(metadata_root),
            HashPart::U64(opened_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn proof_job_id(auction_id: &str, circuit_id: &str, input_root: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-JOB-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(circuit_id),
            HashPart::Str(input_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn reservation_id(job_id: &str, prover_commitment: &str, bid_commitment: &str) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_id),
            HashPart::Str(prover_commitment),
            HashPart::Str(bid_commitment),
        ],
        32,
    )
}

pub fn accelerator_lane_id(
    operator_commitment: &str,
    accelerator_kind: AcceleratorKind,
    workload_kind: ProofWorkloadKind,
    epoch_start_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-ACCELERATOR-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_commitment),
            HashPart::Str(accelerator_kind.as_str()),
            HashPart::Str(workload_kind.as_str()),
            HashPart::U64(epoch_start_height),
        ],
        32,
    )
}

pub fn aggregation_queue_id(
    workload_kind: ProofWorkloadKind,
    input_root: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-AGGREGATION-QUEUE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(workload_kind.as_str()),
            HashPart::Str(input_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn witness_hint_id(job_id: &str, witness_root: &str, owner_commitment: &str) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-WITNESS-HINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_id),
            HashPart::Str(witness_root),
            HashPart::Str(owner_commitment),
        ],
        32,
    )
}

pub fn encrypted_metadata_id(job_id: &str, ciphertext_root: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-ENCRYPTED-METADATA-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_id),
            HashPart::Str(ciphertext_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn qos_id(workload_kind: ProofWorkloadKind, epoch_start_height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-QOS-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(workload_kind.as_str()),
            HashPart::U64(epoch_start_height),
        ],
        32,
    )
}

pub fn verifier_receipt_id(job_id: &str, proof_root: &str, verified_at_height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_id),
            HashPart::Str(proof_root),
            HashPart::U64(verified_at_height),
        ],
        32,
    )
}

pub fn low_fee_rebate_id(job_id: &str, sponsor_commitment: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_id),
            HashPart::Str(sponsor_commitment),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn privacy_fence_id(job_id: &str, nullifier_root: &str, view_tag_root: &str) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_id),
            HashPart::Str(nullifier_root),
            HashPart::Str(view_tag_root),
        ],
        32,
    )
}

pub fn slashing_evidence_id(
    accused_commitment: &str,
    evidence_kind: SlashingEvidenceKind,
    evidence_root: &str,
    filed_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-SLASHING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(accused_commitment),
            HashPart::Str(evidence_kind.as_str()),
            HashPart::Str(evidence_root),
            HashPart::U64(filed_at_height),
        ],
        32,
    )
}

pub fn deterministic_root(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

fn map_root<T, F>(domain: &str, records: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = records.values().map(public_record).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, records: &BTreeSet<String>) -> String {
    let leaves = records
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn empty_roots(config: &Config, counters: &Counters) -> Roots {
    let mut roots = Roots {
        config_root: config.root(),
        counter_root: counters.root(),
        auction_root: merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-AUCTIONS",
            &[],
        ),
        proof_job_root: merkle_root("PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-JOBS", &[]),
        reservation_root: merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-RESERVATIONS",
            &[],
        ),
        accelerator_lane_root: merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-ACCELERATOR-LANES",
            &[],
        ),
        aggregation_queue_root: merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-AGGREGATION-QUEUES",
            &[],
        ),
        witness_hint_root: merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-WITNESS-HINTS",
            &[],
        ),
        encrypted_metadata_root: merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-ENCRYPTED-METADATA",
            &[],
        ),
        latency_qos_root: merkle_root("PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-QOS", &[]),
        verifier_receipt_root: merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-RECEIPTS",
            &[],
        ),
        low_fee_rebate_root: merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-REBATES",
            &[],
        ),
        privacy_fence_root: merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-FENCES",
            &[],
        ),
        slashing_evidence_root: merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-SLASHING",
            &[],
        ),
        active_nullifier_root: merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-NULLIFIERS",
            &[],
        ),
        policy_hint_root: policy_hint_root(),
        public_record_root: merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-PUBLIC-RECORD",
            &[],
        ),
        state_root: String::new(),
    };
    roots.state_root = domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-STATE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(&config.public_record()),
            HashPart::Json(&counters.public_record()),
            HashPart::Json(&roots.public_record()),
        ],
        32,
    );
    roots
}

fn seed_devnet(state: &mut State) {
    let height = DEVNET_HEIGHT;
    for index in 0..8_u64 {
        let workload_kind = match index % 8 {
            0 => ProofWorkloadKind::TransferBatch,
            1 => ProofWorkloadKind::ContractExecution,
            2 => ProofWorkloadKind::MoneroExit,
            3 => ProofWorkloadKind::TokenNetting,
            4 => ProofWorkloadKind::DefiSettlement,
            5 => ProofWorkloadKind::OracleAttestation,
            6 => ProofWorkloadKind::StateDiff,
            _ => ProofWorkloadKind::LowFeeBulk,
        };
        let accelerator_kind = match index % 6 {
            0 => AcceleratorKind::GpuStark,
            1 => AcceleratorKind::FpgaHash,
            2 => AcceleratorKind::AsicMsm,
            3 => AcceleratorKind::RecursiveAggregator,
            4 => AcceleratorKind::WitnessStreamer,
            _ => AcceleratorKind::CpuBatch,
        };
        let metadata_root = deterministic_root(
            "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-DEVNET-METADATA-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(workload_kind.as_str()),
                HashPart::U64(index),
            ],
        );
        let auction_sequence = state.counters.allocate_sequence();
        let auction_id = auction_id(
            workload_kind,
            &metadata_root,
            height + index,
            auction_sequence,
        );
        let bid_root = deterministic_root(
            "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-DEVNET-BID-ROOT",
            &[HashPart::Str(&auction_id), HashPart::U64(index)],
        );
        state.auctions.insert(
            auction_id.clone(),
            ProofJobAuction {
                auction_id: auction_id.clone(),
                sequence: auction_sequence,
                workload_kind,
                status: AuctionStatus::Cleared,
                clearing_rule: AuctionClearingRule::LatencyWeighted,
                encrypted_job_metadata_root: metadata_root.clone(),
                bid_commitment_root: bid_root.clone(),
                reserve_price_piconero: 150_000 + index * 10_000,
                max_fee_piconero: 400_000 + index * 25_000,
                min_bond_piconero: state.config.min_prover_bond_piconero + index * 1_000,
                min_privacy_set_size: state.config.min_privacy_set_size + index * 1_024,
                target_latency_ms: state.config.target_latency_ms + index * 20,
                hard_latency_ms: state.config.hard_latency_ms + index * 30,
                bid_count: 4 + index,
                opened_at_height: height + index,
                closes_at_height: height + index + state.config.auction_ttl_blocks,
                cleared_reservation_id: None,
            },
        );

        let input_root = deterministic_root(
            "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-DEVNET-INPUT-ROOT",
            &[HashPart::Str(&auction_id), HashPart::U64(index)],
        );
        let job_sequence = state.counters.allocate_sequence();
        let job_id = proof_job_id(
            &auction_id,
            "devnet-confidential-circuit",
            &input_root,
            job_sequence,
        );
        let lane_id = accelerator_lane_id(
            &format!("devnet-operator-{index}"),
            accelerator_kind,
            workload_kind,
            height,
        );
        let queue_id = aggregation_queue_id(workload_kind, &input_root, job_sequence);
        let hint_id = witness_hint_id(&job_id, &input_root, &format!("devnet-owner-{index}"));
        let encrypted_metadata_id = encrypted_metadata_id(&job_id, &metadata_root, job_sequence);
        let rebate_id =
            low_fee_rebate_id(&job_id, &format!("devnet-sponsor-{index}"), job_sequence);
        let nullifier_root = deterministic_root(
            "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-DEVNET-NULLIFIER-ROOT",
            &[HashPart::Str(&job_id), HashPart::U64(index)],
        );
        let view_tag_root = deterministic_root(
            "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-DEVNET-VIEWTAG-ROOT",
            &[HashPart::Str(&job_id), HashPart::U64(index)],
        );
        let fence_id = privacy_fence_id(&job_id, &nullifier_root, &view_tag_root);
        let reservation_id = reservation_id(&job_id, &format!("devnet-prover-{index}"), &bid_root);
        let proof_root = deterministic_root(
            "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-DEVNET-PROOF-ROOT",
            &[HashPart::Str(&job_id), HashPart::U64(index)],
        );
        let receipt_id = verifier_receipt_id(&job_id, &proof_root, height + index + 2);
        let qos_id = qos_id(workload_kind, height);

        state.proof_jobs.insert(
            job_id.clone(),
            ProofJob {
                job_id: job_id.clone(),
                sequence: job_sequence,
                auction_id: auction_id.clone(),
                workload_kind,
                status: ProofJobStatus::Verified,
                circuit_id: "devnet-confidential-circuit".to_string(),
                circuit_version: 1,
                proof_system: "pq-recursive-shake-plonkish-devnet".to_string(),
                proving_key_root: deterministic_root(
                    "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-DEVNET-PK",
                    &[HashPart::Str(workload_kind.as_str()), HashPart::U64(index)],
                ),
                public_input_root: input_root.clone(),
                private_input_commitment: deterministic_root(
                    "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-DEVNET-PRIVATE-INPUT",
                    &[HashPart::Str(&job_id), HashPart::U64(index)],
                ),
                witness_hint_id: Some(hint_id.clone()),
                encrypted_metadata_id: Some(encrypted_metadata_id.clone()),
                accelerator_lane_id: Some(lane_id.clone()),
                aggregation_queue_id: Some(queue_id.clone()),
                reservation_id: Some(reservation_id.clone()),
                expected_proof_weight: workload_kind.complexity_weight() + index * 13,
                max_fee_piconero: 400_000 + index * 25_000,
                priority_score: 1_000_000_u64.saturating_sub(index * 1_000),
                pq_security_bits: state.config.min_pq_security_bits,
                privacy_set_size: state.config.min_privacy_set_size + index * 1_024,
                submitted_at_height: height + index,
                expires_at_height: height + index + state.config.job_ttl_blocks,
            },
        );

        state.reservations.insert(
            reservation_id.clone(),
            ProverReservation {
                reservation_id: reservation_id.clone(),
                sequence: state.counters.allocate_sequence(),
                auction_id: auction_id.clone(),
                job_id: job_id.clone(),
                prover_commitment: format!("devnet-prover-{index}"),
                accelerator_lane_id: Some(lane_id.clone()),
                status: ReservationStatus::Paid,
                bid_commitment: bid_root,
                staked_bond_piconero: state.config.min_prover_bond_piconero + index * 1_000,
                quoted_fee_piconero: 220_000 + index * 15_000,
                promised_latency_ms: state.config.target_latency_ms + index * 10,
                pq_attestation_root: deterministic_root(
                    "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-DEVNET-PQ-ATTESTATION",
                    &[HashPart::Str(&job_id), HashPart::U64(index)],
                ),
                scheduler_signature_root: deterministic_root(
                    "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-DEVNET-SCHEDULER-SIG",
                    &[HashPart::Str(&reservation_id), HashPart::U64(index)],
                ),
                reserved_at_height: height + index,
                expires_at_height: height + index + state.config.reservation_ttl_blocks,
            },
        );

        state.accelerator_lanes.insert(
            lane_id.clone(),
            AcceleratorLane {
                lane_id: lane_id.clone(),
                sequence: state.counters.allocate_sequence(),
                accelerator_kind,
                workload_kind,
                status: AcceleratorLaneStatus::Open,
                operator_commitment: format!("devnet-operator-{index}"),
                hardware_attestation_root: deterministic_root(
                    "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-DEVNET-HARDWARE",
                    &[HashPart::Str(&lane_id), HashPart::U64(index)],
                ),
                capacity_weight: 16_000 + index * 500,
                reserved_weight: 4_000 + index * 100,
                target_latency_ms: state.config.target_latency_ms,
                hard_latency_ms: state.config.hard_latency_ms,
                congestion_bps: 1_200 + index * 100,
                base_fee_piconero: 120_000 + index * 5_000,
                epoch_start_height: height,
                epoch_end_height: height + state.config.accelerator_epoch_blocks,
            },
        );

        state.aggregation_queues.insert(
            queue_id.clone(),
            RecursiveAggregationQueue {
                queue_id: queue_id.clone(),
                sequence: state.counters.allocate_sequence(),
                workload_kind,
                status: AggregationQueueStatus::Verified,
                input_job_root: input_root.clone(),
                recursive_vk_root: deterministic_root(
                    "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-DEVNET-RECURSIVE-VK",
                    &[HashPart::Str(workload_kind.as_str()), HashPart::U64(index)],
                ),
                accumulator_root: deterministic_root(
                    "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-DEVNET-ACCUMULATOR",
                    &[HashPart::Str(&queue_id), HashPart::U64(index)],
                ),
                transcript_root: deterministic_root(
                    "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-DEVNET-TRANSCRIPT",
                    &[HashPart::Str(&queue_id), HashPart::U64(index)],
                ),
                queue_depth: 3 + index,
                max_depth: 32,
                target_latency_ms: state.config.target_latency_ms + index * 15,
                base_fee_piconero: 80_000 + index * 4_000,
                opened_at_height: height + index,
                expires_at_height: height + index + state.config.aggregation_ttl_blocks,
            },
        );

        state.witness_hints.insert(
            hint_id.clone(),
            WitnessAvailabilityHint {
                hint_id,
                sequence: state.counters.allocate_sequence(),
                job_id: job_id.clone(),
                status: WitnessHintStatus::Consumed,
                witness_root: input_root.clone(),
                encrypted_witness_blob_root: deterministic_root(
                    "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-DEVNET-WITNESS-BLOB",
                    &[HashPart::Str(&job_id), HashPart::U64(index)],
                ),
                availability_committee_root: deterministic_root(
                    "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-DEVNET-WITNESS-COMMITTEE",
                    &[HashPart::Str(&job_id), HashPart::U64(index)],
                ),
                locality_hint_root: deterministic_root(
                    "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-DEVNET-LOCALITY",
                    &[HashPart::Str(&job_id), HashPart::U64(index)],
                ),
                owner_commitment: format!("devnet-owner-{index}"),
                byte_size: 1_048_576 + index * 16_384,
                privacy_set_size: state.config.min_privacy_set_size + index * 1_024,
                posted_at_height: height + index,
                expires_at_height: height + index + state.config.witness_hint_ttl_blocks,
            },
        );

        state.encrypted_metadata.insert(
            encrypted_metadata_id.clone(),
            EncryptedJobMetadata {
                metadata_id: encrypted_metadata_id,
                sequence: state.counters.allocate_sequence(),
                job_id: job_id.clone(),
                status: EncryptedMetadataStatus::Consumed,
                kem_ciphertext_root: deterministic_root(
                    "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-DEVNET-KEM",
                    &[HashPart::Str(&job_id), HashPart::U64(index)],
                ),
                metadata_ciphertext_root: metadata_root,
                access_policy_root: deterministic_root(
                    "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-DEVNET-ACCESS",
                    &[HashPart::Str(&job_id), HashPart::U64(index)],
                ),
                job_tag_root: deterministic_root(
                    "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-DEVNET-JOB-TAG",
                    &[HashPart::Str(&job_id), HashPart::U64(index)],
                ),
                plaintext_size_commitment: 1_024 + index * 16,
                ciphertext_size: 2_048 + index * 32,
                posted_at_height: height + index,
                expires_at_height: height + index + state.config.metadata_ttl_blocks,
            },
        );

        state.latency_qos.insert(
            qos_id.clone(),
            LatencyQos {
                qos_id,
                sequence: state.counters.allocate_sequence(),
                workload_kind,
                status: LatencyQosStatus::Healthy,
                capacity_weight: 100_000 + index * 1_000,
                reserved_weight: 25_000 + index * 500,
                target_latency_ms: state.config.target_latency_ms,
                hard_latency_ms: state.config.hard_latency_ms,
                observed_p50_latency_ms: state.config.target_latency_ms.saturating_sub(100),
                observed_p95_latency_ms: state.config.target_latency_ms + 300,
                missed_sla_count: index % 2,
                max_fee_bps: state.config.max_user_fee_bps,
                congestion_bps: 900 + index * 50,
                epoch_start_height: height,
                epoch_end_height: height + state.config.qos_epoch_blocks,
            },
        );

        state.verifier_receipts.insert(
            receipt_id.clone(),
            VerifierReceipt {
                receipt_id,
                sequence: state.counters.allocate_sequence(),
                job_id: job_id.clone(),
                reservation_id: reservation_id.clone(),
                status: VerifierReceiptStatus::Finalized,
                verifier_committee_root: deterministic_root(
                    "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-DEVNET-VERIFIER-COMMITTEE",
                    &[HashPart::Str(&job_id), HashPart::U64(index)],
                ),
                proof_root,
                public_input_root: input_root,
                acceptance_root: deterministic_root(
                    "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-DEVNET-ACCEPTANCE",
                    &[HashPart::Str(&job_id), HashPart::U64(index)],
                ),
                latency_observation_root: deterministic_root(
                    "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-DEVNET-LATENCY-OBSERVATION",
                    &[HashPart::Str(&job_id), HashPart::U64(index)],
                ),
                verified_at_height: height + index + 2,
                finalizes_at_height: height + index + 2 + state.config.receipt_finality_blocks,
            },
        );

        state.low_fee_rebates.insert(
            rebate_id.clone(),
            LowFeeRebate {
                rebate_id,
                sequence: state.counters.allocate_sequence(),
                job_id: job_id.clone(),
                reservation_id: Some(reservation_id),
                sponsor_commitment: format!("devnet-sponsor-{index}"),
                status: LowFeeRebateStatus::Settled,
                fee_asset_id: state.config.fee_asset_id.clone(),
                reserved_rebate_piconero: 20_000 + index * 2_000,
                applied_rebate_piconero: 18_000 + index * 1_500,
                max_user_fee_bps: state.config.max_user_fee_bps,
                sponsor_cover_bps: state.config.sponsor_cover_bps,
                reserved_at_height: height + index,
                expires_at_height: height + index + state.config.rebate_ttl_blocks,
            },
        );

        state.privacy_fences.insert(
            fence_id.clone(),
            PrivacyFence {
                fence_id,
                sequence: state.counters.allocate_sequence(),
                job_id: job_id.clone(),
                status: PrivacyFenceStatus::Active,
                nullifier_root: nullifier_root.clone(),
                view_tag_root,
                decoy_set_root: deterministic_root(
                    "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-DEVNET-DECOY",
                    &[HashPart::Str(&job_id), HashPart::U64(index)],
                ),
                disclosure_policy_root: deterministic_root(
                    "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-DEVNET-DISCLOSURE",
                    &[HashPart::Str(&job_id), HashPart::U64(index)],
                ),
                min_privacy_set_size: state.config.min_privacy_set_size,
                opened_at_height: height + index,
                expires_at_height: height + index + state.config.fence_ttl_blocks,
            },
        );

        state.active_nullifiers.insert(nullifier_root);
    }

    let evidence_kind = SlashingEvidenceKind::LatencyBreach;
    let evidence_root = deterministic_root(
        "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-DEVNET-SLASHING-EVIDENCE",
        &[HashPart::Str(CHAIN_ID), HashPart::U64(height)],
    );
    let evidence_id = slashing_evidence_id(
        "devnet-prover-late",
        evidence_kind,
        &evidence_root,
        height + 9,
    );
    state.slashing_evidence.insert(
        evidence_id.clone(),
        SlashingEvidence {
            evidence_id,
            sequence: state.counters.allocate_sequence(),
            accused_commitment: "devnet-prover-late".to_string(),
            job_id: None,
            reservation_id: None,
            receipt_id: None,
            status: SlashingEvidenceStatus::Filed,
            evidence_kind,
            evidence_root,
            reporter_commitment: "devnet-watchtower".to_string(),
            slash_amount_piconero: state.config.min_prover_bond_piconero
                * evidence_kind.slash_bps()
                / MAX_BPS,
            filed_at_height: height + 9,
            expires_at_height: height + 9 + state.config.challenge_window_blocks,
        },
    );
}

pub fn scheduler_policy_catalog() -> Vec<SchedulerPolicyHint> {
    let workloads = [
        ProofWorkloadKind::TransferBatch,
        ProofWorkloadKind::ContractExecution,
        ProofWorkloadKind::MoneroExit,
        ProofWorkloadKind::TokenNetting,
        ProofWorkloadKind::DefiSettlement,
        ProofWorkloadKind::OracleAttestation,
        ProofWorkloadKind::GovernanceTally,
        ProofWorkloadKind::StateDiff,
        ProofWorkloadKind::EmergencyEscape,
        ProofWorkloadKind::LowFeeBulk,
    ];
    let accelerators = [
        AcceleratorKind::CpuBatch,
        AcceleratorKind::GpuStark,
        AcceleratorKind::FpgaHash,
        AcceleratorKind::AsicMsm,
        AcceleratorKind::RecursiveAggregator,
        AcceleratorKind::WitnessStreamer,
        AcceleratorKind::VerifierCommittee,
        AcceleratorKind::EmergencyReserve,
    ];
    let rules = [
        AuctionClearingRule::LowestFeeFirst,
        AuctionClearingRule::LatencyWeighted,
        AuctionClearingRule::BondWeighted,
        AuctionClearingRule::PrivacyWeighted,
        AuctionClearingRule::EmergencyPriority,
        AuctionClearingRule::RebateMaximizing,
    ];
    let mut hints = Vec::new();
    for (workload_index, workload_kind) in workloads.iter().enumerate() {
        for (accelerator_index, accelerator_kind) in accelerators.iter().enumerate() {
            for (rule_index, clearing_rule) in rules.iter().enumerate() {
                let sequence = (workload_index as u64 * 1_000)
                    + (accelerator_index as u64 * 100)
                    + rule_index as u64;
                let domain = format!(
                    "PRIVATE-L2-FAST-PQ-PROVER-SCHEDULER-POLICY-{}-{}-{}",
                    workload_kind.as_str(),
                    accelerator_kind.as_str(),
                    clearing_rule.as_str()
                );
                let hint_id = domain_hash(
                    "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-POLICY-HINT-ID",
                    &[
                        HashPart::Str(CHAIN_ID),
                        HashPart::Str(workload_kind.as_str()),
                        HashPart::Str(accelerator_kind.as_str()),
                        HashPart::Str(clearing_rule.as_str()),
                    ],
                    32,
                );
                hints.push(SchedulerPolicyHint {
                    hint_id,
                    workload_kind: *workload_kind,
                    accelerator_kind: *accelerator_kind,
                    clearing_rule: *clearing_rule,
                    priority_weight: workload_kind
                        .complexity_weight()
                        .saturating_add(accelerator_kind.latency_discount_bps() / 10)
                        .saturating_add(sequence),
                    target_latency_ms: DEFAULT_TARGET_LATENCY_MS
                        .saturating_sub(accelerator_kind.latency_discount_bps() / 20)
                        .max(250),
                    max_fee_bps: DEFAULT_MAX_USER_FEE_BPS + (rule_index as u64 % 3),
                    min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE
                        + workload_index as u64 * 1_024,
                    domain,
                });
            }
        }
    }
    hints
}

pub fn policy_hint_root() -> String {
    let leaves = scheduler_policy_catalog()
        .into_iter()
        .map(|hint| hint.public_record())
        .collect::<Vec<_>>();
    merkle_root(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PROVER-SCHEDULER-POLICY-HINT-CATALOG",
        &leaves,
    )
}
