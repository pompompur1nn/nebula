use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::hash::{Hash, Hasher};

pub type LoadSheddingResult<T> = Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_EXECUTION_LOAD_SHEDDING_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-execution-load-shedding-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_EXECUTION_LOAD_SHEDDING_PROTOCOL_VERSION;
pub const MODULE_PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_EXECUTION_LOAD_SHEDDING_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_DOMAIN: &str = "NEBULA-PRIVATE-L2-FAST-PQ-LOAD-SHEDDING";
pub const ROOT_DOMAIN: &str = "NEBULA-PRIVATE-L2-FAST-PQ-LOAD-SHEDDING-ROOT";
pub const RECORD_DOMAIN: &str = "NEBULA-PRIVATE-L2-FAST-PQ-LOAD-SHEDDING-RECORD";
pub const TELEMETRY_DOMAIN: &str = "NEBULA-PRIVATE-L2-FAST-PQ-LOAD-SHEDDING-TELEMETRY";
pub const PQ_ATTESTATION_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-192s";
pub const PQ_KEM_SUITE: &str = "ML-KEM-1024";
pub const CONFIDENTIAL_COMMITMENT_SUITE: &str = "pedersen-poseidon-note-root-v1";
pub const PRIVATE_MEMPOOL_FAIRNESS_SUITE: &str = "sealed-bucket-virtual-finish-time-v1";
pub const WITNESS_PREFETCH_SUITE: &str = "encrypted-witness-prefetch-bloom-root-v1";
pub const TELEMETRY_PRIVACY_SUITE: &str = "differential-bucket-commitment-no-user-metadata-v1";
pub const DEFAULT_CHAIN_ID: &str = "nebula-devnet";
pub const DEFAULT_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const DEFAULT_LOW_FEE_ASSET_ID: &str = "dusd-devnet";
pub const DEFAULT_TARGET_BLOCK_MS: u64 = 500;
pub const DEFAULT_MAX_BLOCK_WEIGHT: u64 = 1_250_000;
pub const DEFAULT_MAX_PRIVATE_MEMPOOL_ITEMS: usize = 8192;
pub const DEFAULT_MAX_PRECONFIRMATION_INFLIGHT: u64 = 2048;
pub const DEFAULT_MAX_PROVER_JOBS: u64 = 8192;
pub const DEFAULT_MAX_WITNESS_PREFETCH_BYTES: u64 = 512 * 1024 * 1024;
pub const DEFAULT_MAX_CONTRACT_HOTSPOT_WEIGHT: u64 = 300_000;
pub const DEFAULT_LOW_FEE_RESERVE_BPS: u64 = 1_500;
pub const DEFAULT_EMERGENCY_RESERVE_BPS: u64 = 1_000;
pub const DEFAULT_PRIVATE_FAIRNESS_WINDOW: u64 = 64;
pub const DEFAULT_TELEMETRY_BUCKET_WIDTH: u64 = 16;
pub const DEFAULT_MAX_USER_FEE_CAP_UNITS: u64 = 25_000;
pub const DEFAULT_MIN_LOW_FEE_CAP_UNITS: u64 = 250;
pub const DEFAULT_BASE_FEE_UNITS: u64 = 100;
pub const DEFAULT_PQ_SURCHARGE_UNITS: u64 = 16;
pub const DEFAULT_PREFETCH_BYTE_PRICE_UNITS: u64 = 1;
pub const DEFAULT_PROVER_JOB_PRICE_UNITS: u64 = 5;
pub const DEFAULT_CONGESTION_WARN_BPS: u64 = 7_000;
pub const DEFAULT_CONGESTION_CRITICAL_BPS: u64 = 9_000;
pub const DEFAULT_CONGESTION_HALT_BPS: u64 = 9_800;
pub const DEFAULT_MAX_RECENT_RECORDS: usize = 512;
pub const DEFAULT_MAX_TELEMETRY_BUCKETS: usize = 256;
pub const DEFAULT_MAX_HOTSPOTS: usize = 512;
pub const DEFAULT_MAX_ACCOUNTS_PER_ROUND: usize = 4096;
pub const DEFAULT_MIN_ANONYMITY_SET: u64 = 32;
pub const DEFAULT_EPOCH_BLOCKS: u64 = 240;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneKind {
    MoneroShieldedTransfer,
    MoneroBridgeDeposit,
    MoneroBridgeWithdrawal,
    TokenTransfer,
    TokenLaunch,
    PrivateSwap,
    PrivateLending,
    ConfidentialContractCall,
    ContractDeployment,
    SmartWalletSession,
    ProofSubmission,
    WitnessPrefetch,
    LowFeeRescue,
    EmergencyExit,
    Governance,
    BulkSettlement,
}

impl LaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroShieldedTransfer => "monero_shielded_transfer",
            Self::MoneroBridgeDeposit => "monero_bridge_deposit",
            Self::MoneroBridgeWithdrawal => "monero_bridge_withdrawal",
            Self::TokenTransfer => "token_transfer",
            Self::TokenLaunch => "token_launch",
            Self::PrivateSwap => "private_swap",
            Self::PrivateLending => "private_lending",
            Self::ConfidentialContractCall => "confidential_contract_call",
            Self::ContractDeployment => "contract_deployment",
            Self::SmartWalletSession => "smart_wallet_session",
            Self::ProofSubmission => "proof_submission",
            Self::WitnessPrefetch => "witness_prefetch",
            Self::LowFeeRescue => "low_fee_rescue",
            Self::EmergencyExit => "emergency_exit",
            Self::Governance => "governance",
            Self::BulkSettlement => "bulk_settlement",
        }
    }

    pub fn default_weight(self) -> u64 {
        match self {
            Self::EmergencyExit => 10_000,
            Self::MoneroBridgeWithdrawal => 9_300,
            Self::LowFeeRescue => 8_900,
            Self::MoneroShieldedTransfer => 8_600,
            Self::PrivateSwap => 8_200,
            Self::MoneroBridgeDeposit => 8_000,
            Self::TokenTransfer => 7_200,
            Self::SmartWalletSession => 7_000,
            Self::PrivateLending => 6_800,
            Self::ConfidentialContractCall => 6_500,
            Self::TokenLaunch => 5_800,
            Self::ProofSubmission => 5_600,
            Self::WitnessPrefetch => 5_200,
            Self::ContractDeployment => 4_800,
            Self::Governance => 3_600,
            Self::BulkSettlement => 2_200,
        }
    }

    pub fn default_sla_ms(self) -> u64 {
        match self {
            Self::EmergencyExit => 250,
            Self::MoneroBridgeWithdrawal => 350,
            Self::MoneroShieldedTransfer => 450,
            Self::PrivateSwap => 450,
            Self::MoneroBridgeDeposit => 500,
            Self::LowFeeRescue => 650,
            Self::TokenTransfer => 700,
            Self::SmartWalletSession => 700,
            Self::PrivateLending => 850,
            Self::ConfidentialContractCall => 900,
            Self::TokenLaunch => 1_000,
            Self::ProofSubmission => 1_250,
            Self::WitnessPrefetch => 1_500,
            Self::ContractDeployment => 1_750,
            Self::Governance => 2_000,
            Self::BulkSettlement => 4_000,
        }
    }

    pub fn default_quantum_cost(self) -> u64 {
        match self {
            Self::EmergencyExit => 2,
            Self::MoneroShieldedTransfer => 3,
            Self::MoneroBridgeDeposit => 4,
            Self::MoneroBridgeWithdrawal => 4,
            Self::TokenTransfer => 2,
            Self::TokenLaunch => 5,
            Self::PrivateSwap => 5,
            Self::PrivateLending => 5,
            Self::ConfidentialContractCall => 6,
            Self::ContractDeployment => 8,
            Self::SmartWalletSession => 3,
            Self::ProofSubmission => 7,
            Self::WitnessPrefetch => 2,
            Self::LowFeeRescue => 3,
            Self::Governance => 4,
            Self::BulkSettlement => 2,
        }
    }

    pub fn privacy_critical(self) -> bool {
        matches!(
            self,
            Self::MoneroShieldedTransfer
                | Self::MoneroBridgeDeposit
                | Self::MoneroBridgeWithdrawal
                | Self::PrivateSwap
                | Self::PrivateLending
                | Self::ConfidentialContractCall
                | Self::SmartWalletSession
                | Self::LowFeeRescue
                | Self::EmergencyExit
        )
    }

    pub fn low_fee_eligible(self) -> bool {
        matches!(
            self,
            Self::MoneroShieldedTransfer
                | Self::TokenTransfer
                | Self::SmartWalletSession
                | Self::LowFeeRescue
                | Self::EmergencyExit
        )
    }

    pub fn contract_sensitive(self) -> bool {
        matches!(
            self,
            Self::ConfidentialContractCall
                | Self::ContractDeployment
                | Self::PrivateSwap
                | Self::PrivateLending
                | Self::TokenLaunch
        )
    }

    pub fn all() -> Vec<Self> {
        vec![
            Self::MoneroShieldedTransfer,
            Self::MoneroBridgeDeposit,
            Self::MoneroBridgeWithdrawal,
            Self::TokenTransfer,
            Self::TokenLaunch,
            Self::PrivateSwap,
            Self::PrivateLending,
            Self::ConfidentialContractCall,
            Self::ContractDeployment,
            Self::SmartWalletSession,
            Self::ProofSubmission,
            Self::WitnessPrefetch,
            Self::LowFeeRescue,
            Self::EmergencyExit,
            Self::Governance,
            Self::BulkSettlement,
        ]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueClass {
    Emergency,
    FastPrivate,
    StandardPrivate,
    LowFee,
    Prover,
    Witness,
    Contract,
    Bulk,
}

impl QueueClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Emergency => "emergency",
            Self::FastPrivate => "fast_private",
            Self::StandardPrivate => "standard_private",
            Self::LowFee => "low_fee",
            Self::Prover => "prover",
            Self::Witness => "witness",
            Self::Contract => "contract",
            Self::Bulk => "bulk",
        }
    }

    pub fn from_lane(lane: LaneKind, low_fee: bool) -> Self {
        if matches!(lane, LaneKind::EmergencyExit) {
            Self::Emergency
        } else if low_fee || matches!(lane, LaneKind::LowFeeRescue) {
            Self::LowFee
        } else if matches!(lane, LaneKind::ProofSubmission) {
            Self::Prover
        } else if matches!(lane, LaneKind::WitnessPrefetch) {
            Self::Witness
        } else if lane.contract_sensitive() {
            Self::Contract
        } else if matches!(lane, LaneKind::BulkSettlement | LaneKind::Governance) {
            Self::Bulk
        } else if lane.privacy_critical() {
            Self::FastPrivate
        } else {
            Self::StandardPrivate
        }
    }

    pub fn all() -> Vec<Self> {
        vec![
            Self::Emergency,
            Self::FastPrivate,
            Self::StandardPrivate,
            Self::LowFee,
            Self::Prover,
            Self::Witness,
            Self::Contract,
            Self::Bulk,
        ]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadLevel {
    Open,
    Warm,
    Congested,
    Critical,
    Shedding,
    Halted,
}

impl LoadLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Warm => "warm",
            Self::Congested => "congested",
            Self::Critical => "critical",
            Self::Shedding => "shedding",
            Self::Halted => "halted",
        }
    }

    pub fn from_bps(utilization_bps: u64, warn_bps: u64, critical_bps: u64, halt_bps: u64) -> Self {
        if utilization_bps >= halt_bps {
            Self::Halted
        } else if utilization_bps >= critical_bps.saturating_add(halt_bps).saturating_div(2) {
            Self::Shedding
        } else if utilization_bps >= critical_bps {
            Self::Critical
        } else if utilization_bps >= warn_bps {
            Self::Congested
        } else if utilization_bps >= warn_bps.saturating_div(2) {
            Self::Warm
        } else {
            Self::Open
        }
    }

    pub fn admits_nonessential(self) -> bool {
        matches!(self, Self::Open | Self::Warm | Self::Congested)
    }

    pub fn multiplier_bps(self) -> u64 {
        match self {
            Self::Open => 10_000,
            Self::Warm => 11_000,
            Self::Congested => 13_500,
            Self::Critical => 17_500,
            Self::Shedding => 22_500,
            Self::Halted => 50_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionDecision {
    Admit,
    AdmitLowFee,
    AdmitEmergency,
    Defer,
    Shed,
    RejectFeeCap,
    RejectPrivacyBudget,
    RejectHotSpot,
    RejectDuplicate,
    RejectMalformed,
}

impl AdmissionDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::AdmitLowFee => "admit_low_fee",
            Self::AdmitEmergency => "admit_emergency",
            Self::Defer => "defer",
            Self::Shed => "shed",
            Self::RejectFeeCap => "reject_fee_cap",
            Self::RejectPrivacyBudget => "reject_privacy_budget",
            Self::RejectHotSpot => "reject_hot_spot",
            Self::RejectDuplicate => "reject_duplicate",
            Self::RejectMalformed => "reject_malformed",
        }
    }

    pub fn accepted(self) -> bool {
        matches!(self, Self::Admit | Self::AdmitLowFee | Self::AdmitEmergency)
    }

    pub fn rejected(self) -> bool {
        matches!(
            self,
            Self::RejectFeeCap
                | Self::RejectPrivacyBudget
                | Self::RejectHotSpot
                | Self::RejectDuplicate
                | Self::RejectMalformed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SheddingAction {
    None,
    DelayBulk,
    DelayWitness,
    CapContractHotSpot,
    ProverQueueBackpressure,
    PreconfirmationThrottle,
    LowFeeOnly,
    EmergencyOnly,
    HaltNewAdmission,
}

impl SheddingAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::DelayBulk => "delay_bulk",
            Self::DelayWitness => "delay_witness",
            Self::CapContractHotSpot => "cap_contract_hot_spot",
            Self::ProverQueueBackpressure => "prover_queue_backpressure",
            Self::PreconfirmationThrottle => "preconfirmation_throttle",
            Self::LowFeeOnly => "low_fee_only",
            Self::EmergencyOnly => "emergency_only",
            Self::HaltNewAdmission => "halt_new_admission",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyMode {
    Normal,
    Guarded,
    LowFeeProtected,
    ExitOnly,
    SequencerRecovery,
    FullHalt,
}

impl EmergencyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Guarded => "guarded",
            Self::LowFeeProtected => "low_fee_protected",
            Self::ExitOnly => "exit_only",
            Self::SequencerRecovery => "sequencer_recovery",
            Self::FullHalt => "full_halt",
        }
    }

    pub fn allows_lane(self, lane: LaneKind) -> bool {
        match self {
            Self::Normal => true,
            Self::Guarded => !matches!(lane, LaneKind::BulkSettlement | LaneKind::Governance),
            Self::LowFeeProtected => lane.low_fee_eligible() || lane.privacy_critical(),
            Self::ExitOnly => matches!(
                lane,
                LaneKind::EmergencyExit | LaneKind::MoneroBridgeWithdrawal
            ),
            Self::SequencerRecovery => matches!(
                lane,
                LaneKind::EmergencyExit
                    | LaneKind::MoneroBridgeWithdrawal
                    | LaneKind::LowFeeRescue
                    | LaneKind::ProofSubmission
            ),
            Self::FullHalt => matches!(lane, LaneKind::EmergencyExit),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HotSpotClass {
    Cold,
    Warm,
    Hot,
    Saturated,
    Quarantined,
}

impl HotSpotClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cold => "cold",
            Self::Warm => "warm",
            Self::Hot => "hot",
            Self::Saturated => "saturated",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn from_weight(weight: u64, cap: u64) -> Self {
        if cap == 0 {
            Self::Quarantined
        } else {
            let bps = weight.saturating_mul(MAX_BPS) / cap.max(1);
            if bps >= 12_000 {
                Self::Quarantined
            } else if bps >= 10_000 {
                Self::Saturated
            } else if bps >= 8_000 {
                Self::Hot
            } else if bps >= 4_000 {
                Self::Warm
            } else {
                Self::Cold
            }
        }
    }

    pub fn accepts_new_work(self) -> bool {
        matches!(self, Self::Cold | Self::Warm | Self::Hot)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyTelemetryClass {
    Hidden,
    Bucketed,
    CoarseAggregate,
    PublicRootOnly,
}

impl PrivacyTelemetryClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hidden => "hidden",
            Self::Bucketed => "bucketed",
            Self::CoarseAggregate => "coarse_aggregate",
            Self::PublicRootOnly => "public_root_only",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeCapStatus {
    Satisfied,
    Tight,
    TooLow,
    Sponsored,
    LowFeeCredit,
}

impl FeeCapStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Satisfied => "satisfied",
            Self::Tight => "tight",
            Self::TooLow => "too_low",
            Self::Sponsored => "sponsored",
            Self::LowFeeCredit => "low_fee_credit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    None,
    SequencerCongestion,
    PreconfirmationLoad,
    ProverBacklog,
    WitnessPrefetchPressure,
    ContractHotSpot,
    PrivateMempoolFairness,
    UserFeeCap,
    LowFeeLaneReserve,
    EmergencyAdmissionControl,
    PrivacyTelemetryBudget,
    DuplicateNullifier,
    MalformedCommitment,
}

impl ReasonCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SequencerCongestion => "sequencer_congestion",
            Self::PreconfirmationLoad => "preconfirmation_load",
            Self::ProverBacklog => "prover_backlog",
            Self::WitnessPrefetchPressure => "witness_prefetch_pressure",
            Self::ContractHotSpot => "contract_hot_spot",
            Self::PrivateMempoolFairness => "private_mempool_fairness",
            Self::UserFeeCap => "user_fee_cap",
            Self::LowFeeLaneReserve => "low_fee_lane_reserve",
            Self::EmergencyAdmissionControl => "emergency_admission_control",
            Self::PrivacyTelemetryBudget => "privacy_telemetry_budget",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::MalformedCommitment => "malformed_commitment",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub fee_asset_id: String,
    pub low_fee_asset_id: String,
    pub pq_attestation_suite: String,
    pub pq_kem_suite: String,
    pub confidential_commitment_suite: String,
    pub private_mempool_fairness_suite: String,
    pub witness_prefetch_suite: String,
    pub telemetry_privacy_suite: String,
    pub target_block_ms: u64,
    pub max_block_weight: u64,
    pub max_private_mempool_items: usize,
    pub max_preconfirmation_inflight: u64,
    pub max_prover_jobs: u64,
    pub max_witness_prefetch_bytes: u64,
    pub max_contract_hotspot_weight: u64,
    pub low_fee_reserve_bps: u64,
    pub emergency_reserve_bps: u64,
    pub private_fairness_window: u64,
    pub telemetry_bucket_width: u64,
    pub max_user_fee_cap_units: u64,
    pub min_low_fee_cap_units: u64,
    pub base_fee_units: u64,
    pub pq_surcharge_units: u64,
    pub prefetch_byte_price_units: u64,
    pub prover_job_price_units: u64,
    pub congestion_warn_bps: u64,
    pub congestion_critical_bps: u64,
    pub congestion_halt_bps: u64,
    pub max_recent_records: usize,
    pub max_telemetry_buckets: usize,
    pub max_hotspots: usize,
    pub max_accounts_per_round: usize,
    pub min_anonymity_set: u64,
    pub epoch_blocks: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: DEFAULT_CHAIN_ID.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            low_fee_asset_id: DEFAULT_LOW_FEE_ASSET_ID.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            pq_kem_suite: PQ_KEM_SUITE.to_string(),
            confidential_commitment_suite: CONFIDENTIAL_COMMITMENT_SUITE.to_string(),
            private_mempool_fairness_suite: PRIVATE_MEMPOOL_FAIRNESS_SUITE.to_string(),
            witness_prefetch_suite: WITNESS_PREFETCH_SUITE.to_string(),
            telemetry_privacy_suite: TELEMETRY_PRIVACY_SUITE.to_string(),
            target_block_ms: DEFAULT_TARGET_BLOCK_MS,
            max_block_weight: DEFAULT_MAX_BLOCK_WEIGHT,
            max_private_mempool_items: DEFAULT_MAX_PRIVATE_MEMPOOL_ITEMS,
            max_preconfirmation_inflight: DEFAULT_MAX_PRECONFIRMATION_INFLIGHT,
            max_prover_jobs: DEFAULT_MAX_PROVER_JOBS,
            max_witness_prefetch_bytes: DEFAULT_MAX_WITNESS_PREFETCH_BYTES,
            max_contract_hotspot_weight: DEFAULT_MAX_CONTRACT_HOTSPOT_WEIGHT,
            low_fee_reserve_bps: DEFAULT_LOW_FEE_RESERVE_BPS,
            emergency_reserve_bps: DEFAULT_EMERGENCY_RESERVE_BPS,
            private_fairness_window: DEFAULT_PRIVATE_FAIRNESS_WINDOW,
            telemetry_bucket_width: DEFAULT_TELEMETRY_BUCKET_WIDTH,
            max_user_fee_cap_units: DEFAULT_MAX_USER_FEE_CAP_UNITS,
            min_low_fee_cap_units: DEFAULT_MIN_LOW_FEE_CAP_UNITS,
            base_fee_units: DEFAULT_BASE_FEE_UNITS,
            pq_surcharge_units: DEFAULT_PQ_SURCHARGE_UNITS,
            prefetch_byte_price_units: DEFAULT_PREFETCH_BYTE_PRICE_UNITS,
            prover_job_price_units: DEFAULT_PROVER_JOB_PRICE_UNITS,
            congestion_warn_bps: DEFAULT_CONGESTION_WARN_BPS,
            congestion_critical_bps: DEFAULT_CONGESTION_CRITICAL_BPS,
            congestion_halt_bps: DEFAULT_CONGESTION_HALT_BPS,
            max_recent_records: DEFAULT_MAX_RECENT_RECORDS,
            max_telemetry_buckets: DEFAULT_MAX_TELEMETRY_BUCKETS,
            max_hotspots: DEFAULT_MAX_HOTSPOTS,
            max_accounts_per_round: DEFAULT_MAX_ACCOUNTS_PER_ROUND,
            min_anonymity_set: DEFAULT_MIN_ANONYMITY_SET,
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn demo() -> Self {
        Self {
            max_block_weight: 240_000,
            max_private_mempool_items: 512,
            max_preconfirmation_inflight: 256,
            max_prover_jobs: 768,
            max_witness_prefetch_bytes: 64 * 1024 * 1024,
            max_contract_hotspot_weight: 60_000,
            low_fee_reserve_bps: 2_000,
            emergency_reserve_bps: 1_500,
            telemetry_bucket_width: 8,
            max_recent_records: 128,
            max_telemetry_buckets: 96,
            max_hotspots: 96,
            ..Self::default()
        }
    }

    pub fn validate(&self) -> LoadSheddingResult<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("invalid protocol version".to_string());
        }
        if self.chain_id.is_empty() {
            return Err("missing chain id".to_string());
        }
        if self.target_block_ms == 0 {
            return Err("target block time must be nonzero".to_string());
        }
        if self.max_block_weight == 0 {
            return Err("max block weight must be nonzero".to_string());
        }
        if self
            .low_fee_reserve_bps
            .saturating_add(self.emergency_reserve_bps)
            > MAX_BPS
        {
            return Err("lane reserves exceed 100 percent".to_string());
        }
        if self.congestion_warn_bps > self.congestion_critical_bps {
            return Err("warn threshold exceeds critical threshold".to_string());
        }
        if self.congestion_critical_bps > self.congestion_halt_bps {
            return Err("critical threshold exceeds halt threshold".to_string());
        }
        if self.congestion_halt_bps > MAX_BPS {
            return Err("halt threshold exceeds max bps".to_string());
        }
        if self.max_private_mempool_items == 0 {
            return Err("private mempool capacity must be nonzero".to_string());
        }
        if self.max_recent_records == 0 {
            return Err("recent record capacity must be nonzero".to_string());
        }
        if self.telemetry_bucket_width == 0 {
            return Err("telemetry bucket width must be nonzero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "fee_asset_id": self.fee_asset_id,
            "low_fee_asset_id": self.low_fee_asset_id,
            "pq_attestation_suite": self.pq_attestation_suite,
            "pq_kem_suite": self.pq_kem_suite,
            "confidential_commitment_suite": self.confidential_commitment_suite,
            "private_mempool_fairness_suite": self.private_mempool_fairness_suite,
            "witness_prefetch_suite": self.witness_prefetch_suite,
            "telemetry_privacy_suite": self.telemetry_privacy_suite,
            "target_block_ms": self.target_block_ms,
            "max_block_weight": self.max_block_weight,
            "max_private_mempool_items": self.max_private_mempool_items,
            "max_preconfirmation_inflight": self.max_preconfirmation_inflight,
            "max_prover_jobs": self.max_prover_jobs,
            "max_witness_prefetch_bytes": self.max_witness_prefetch_bytes,
            "max_contract_hotspot_weight": self.max_contract_hotspot_weight,
            "low_fee_reserve_bps": self.low_fee_reserve_bps,
            "emergency_reserve_bps": self.emergency_reserve_bps,
            "private_fairness_window": self.private_fairness_window,
            "telemetry_bucket_width": self.telemetry_bucket_width,
            "max_user_fee_cap_units": self.max_user_fee_cap_units,
            "min_low_fee_cap_units": self.min_low_fee_cap_units,
            "base_fee_units": self.base_fee_units,
            "pq_surcharge_units": self.pq_surcharge_units,
            "prefetch_byte_price_units": self.prefetch_byte_price_units,
            "prover_job_price_units": self.prover_job_price_units,
            "congestion_warn_bps": self.congestion_warn_bps,
            "congestion_critical_bps": self.congestion_critical_bps,
            "congestion_halt_bps": self.congestion_halt_bps,
            "max_recent_records": self.max_recent_records,
            "max_telemetry_buckets": self.max_telemetry_buckets,
            "max_hotspots": self.max_hotspots,
            "max_accounts_per_round": self.max_accounts_per_round,
            "min_anonymity_set": self.min_anonymity_set,
            "epoch_blocks": self.epoch_blocks,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub requests_seen: u64,
    pub admitted: u64,
    pub admitted_low_fee: u64,
    pub admitted_emergency: u64,
    pub deferred: u64,
    pub shed: u64,
    pub rejected_fee_cap: u64,
    pub rejected_privacy_budget: u64,
    pub rejected_hotspot: u64,
    pub rejected_duplicate: u64,
    pub rejected_malformed: u64,
    pub planned_batches: u64,
    pub planned_items: u64,
    pub planned_weight: u64,
    pub preconfirmations_throttled: u64,
    pub prover_jobs_throttled: u64,
    pub witness_prefetch_throttled: u64,
    pub contract_hotspot_throttled: u64,
    pub fee_cap_saves: u64,
    pub low_fee_reserved_weight: u64,
    pub emergency_reserved_weight: u64,
    pub telemetry_exports: u64,
}

impl Counters {
    pub fn observe_decision(&mut self, decision: AdmissionDecision) {
        self.requests_seen = self.requests_seen.saturating_add(1);
        match decision {
            AdmissionDecision::Admit => self.admitted = self.admitted.saturating_add(1),
            AdmissionDecision::AdmitLowFee => {
                self.admitted_low_fee = self.admitted_low_fee.saturating_add(1)
            }
            AdmissionDecision::AdmitEmergency => {
                self.admitted_emergency = self.admitted_emergency.saturating_add(1)
            }
            AdmissionDecision::Defer => self.deferred = self.deferred.saturating_add(1),
            AdmissionDecision::Shed => self.shed = self.shed.saturating_add(1),
            AdmissionDecision::RejectFeeCap => {
                self.rejected_fee_cap = self.rejected_fee_cap.saturating_add(1)
            }
            AdmissionDecision::RejectPrivacyBudget => {
                self.rejected_privacy_budget = self.rejected_privacy_budget.saturating_add(1)
            }
            AdmissionDecision::RejectHotSpot => {
                self.rejected_hotspot = self.rejected_hotspot.saturating_add(1)
            }
            AdmissionDecision::RejectDuplicate => {
                self.rejected_duplicate = self.rejected_duplicate.saturating_add(1)
            }
            AdmissionDecision::RejectMalformed => {
                self.rejected_malformed = self.rejected_malformed.saturating_add(1)
            }
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "requests_seen": self.requests_seen,
            "admitted": self.admitted,
            "admitted_low_fee": self.admitted_low_fee,
            "admitted_emergency": self.admitted_emergency,
            "deferred": self.deferred,
            "shed": self.shed,
            "rejected_fee_cap": self.rejected_fee_cap,
            "rejected_privacy_budget": self.rejected_privacy_budget,
            "rejected_hotspot": self.rejected_hotspot,
            "rejected_duplicate": self.rejected_duplicate,
            "rejected_malformed": self.rejected_malformed,
            "planned_batches": self.planned_batches,
            "planned_items": self.planned_items,
            "planned_weight": self.planned_weight,
            "preconfirmations_throttled": self.preconfirmations_throttled,
            "prover_jobs_throttled": self.prover_jobs_throttled,
            "witness_prefetch_throttled": self.witness_prefetch_throttled,
            "contract_hotspot_throttled": self.contract_hotspot_throttled,
            "fee_cap_saves": self.fee_cap_saves,
            "low_fee_reserved_weight": self.low_fee_reserved_weight,
            "emergency_reserved_weight": self.emergency_reserved_weight,
            "telemetry_exports": self.telemetry_exports,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub lane_root: String,
    pub queue_root: String,
    pub request_root: String,
    pub admission_root: String,
    pub prover_root: String,
    pub witness_root: String,
    pub hotspot_root: String,
    pub fee_cap_root: String,
    pub fairness_root: String,
    pub telemetry_root: String,
    pub emergency_root: String,
    pub counters_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "queue_root": self.queue_root,
            "request_root": self.request_root,
            "admission_root": self.admission_root,
            "prover_root": self.prover_root,
            "witness_root": self.witness_root,
            "hotspot_root": self.hotspot_root,
            "fee_cap_root": self.fee_cap_root,
            "fairness_root": self.fairness_root,
            "telemetry_root": self.telemetry_root,
            "emergency_root": self.emergency_root,
            "counters_root": self.counters_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneState {
    pub lane: LaneKind,
    pub enabled: bool,
    pub queue_class: QueueClass,
    pub weight: u64,
    pub sla_ms: u64,
    pub quantum_cost: u64,
    pub admitted_count: u64,
    pub deferred_count: u64,
    pub shed_count: u64,
    pub inflight_weight: u64,
    pub planned_weight: u64,
    pub load_level: LoadLevel,
    pub shedding_action: SheddingAction,
}

impl LaneState {
    pub fn new(lane: LaneKind) -> Self {
        Self {
            lane,
            enabled: true,
            queue_class: QueueClass::from_lane(lane, matches!(lane, LaneKind::LowFeeRescue)),
            weight: lane.default_weight(),
            sla_ms: lane.default_sla_ms(),
            quantum_cost: lane.default_quantum_cost(),
            admitted_count: 0,
            deferred_count: 0,
            shed_count: 0,
            inflight_weight: 0,
            planned_weight: 0,
            load_level: LoadLevel::Open,
            shedding_action: SheddingAction::None,
        }
    }

    pub fn observe_decision(&mut self, decision: AdmissionDecision, request_weight: u64) {
        match decision {
            AdmissionDecision::Admit
            | AdmissionDecision::AdmitLowFee
            | AdmissionDecision::AdmitEmergency => {
                self.admitted_count = self.admitted_count.saturating_add(1);
                self.inflight_weight = self.inflight_weight.saturating_add(request_weight);
            }
            AdmissionDecision::Defer => {
                self.deferred_count = self.deferred_count.saturating_add(1);
            }
            AdmissionDecision::Shed
            | AdmissionDecision::RejectFeeCap
            | AdmissionDecision::RejectPrivacyBudget
            | AdmissionDecision::RejectHotSpot
            | AdmissionDecision::RejectDuplicate
            | AdmissionDecision::RejectMalformed => {
                self.shed_count = self.shed_count.saturating_add(1);
            }
        }
    }

    pub fn utilization_bps(&self, config: &Config) -> u64 {
        self.inflight_weight
            .saturating_mul(MAX_BPS)
            .saturating_div(config.max_block_weight.max(1))
            .min(MAX_BPS.saturating_mul(2))
    }

    pub fn refresh_load(&mut self, config: &Config) {
        let bps = self.utilization_bps(config);
        self.load_level = LoadLevel::from_bps(
            bps,
            config.congestion_warn_bps,
            config.congestion_critical_bps,
            config.congestion_halt_bps,
        );
        self.shedding_action = match self.load_level {
            LoadLevel::Open | LoadLevel::Warm => SheddingAction::None,
            LoadLevel::Congested => {
                if matches!(self.queue_class, QueueClass::Bulk) {
                    SheddingAction::DelayBulk
                } else if matches!(self.queue_class, QueueClass::Witness) {
                    SheddingAction::DelayWitness
                } else {
                    SheddingAction::None
                }
            }
            LoadLevel::Critical => {
                if self.lane.contract_sensitive() {
                    SheddingAction::CapContractHotSpot
                } else if matches!(self.queue_class, QueueClass::Prover) {
                    SheddingAction::ProverQueueBackpressure
                } else {
                    SheddingAction::PreconfirmationThrottle
                }
            }
            LoadLevel::Shedding => SheddingAction::LowFeeOnly,
            LoadLevel::Halted => SheddingAction::HaltNewAdmission,
        };
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "enabled": self.enabled,
            "queue_class": self.queue_class.as_str(),
            "weight": self.weight,
            "sla_ms": self.sla_ms,
            "quantum_cost": self.quantum_cost,
            "admitted_count": self.admitted_count,
            "deferred_count": self.deferred_count,
            "shed_count": self.shed_count,
            "inflight_weight": self.inflight_weight,
            "planned_weight": self.planned_weight,
            "load_level": self.load_level.as_str(),
            "shedding_action": self.shedding_action.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRequest {
    pub request_id: String,
    pub account_bucket: String,
    pub lane: LaneKind,
    pub queue_class: QueueClass,
    pub payload_commitment: String,
    pub nullifier_commitment: String,
    pub contract_commitment: String,
    pub witness_root: String,
    pub fee_cap_units: u64,
    pub offered_fee_units: u64,
    pub estimated_weight: u64,
    pub estimated_prover_jobs: u64,
    pub estimated_witness_bytes: u64,
    pub preconfirmation_requested: bool,
    pub low_fee_requested: bool,
    pub emergency: bool,
    pub privacy_budget: u64,
    pub anonymity_set: u64,
    pub epoch: u64,
    pub sequence: u64,
}

impl ExecutionRequest {
    pub fn new(
        request_id: &str,
        account_bucket: &str,
        lane: LaneKind,
        payload_commitment: &str,
        nullifier_commitment: &str,
    ) -> Self {
        Self {
            request_id: request_id.to_string(),
            account_bucket: account_bucket.to_string(),
            lane,
            queue_class: QueueClass::from_lane(lane, false),
            payload_commitment: payload_commitment.to_string(),
            nullifier_commitment: nullifier_commitment.to_string(),
            contract_commitment: "none".to_string(),
            witness_root: "none".to_string(),
            fee_cap_units: DEFAULT_MAX_USER_FEE_CAP_UNITS,
            offered_fee_units: DEFAULT_BASE_FEE_UNITS,
            estimated_weight: lane.default_weight(),
            estimated_prover_jobs: lane.default_quantum_cost(),
            estimated_witness_bytes: 0,
            preconfirmation_requested: lane.privacy_critical(),
            low_fee_requested: false,
            emergency: matches!(lane, LaneKind::EmergencyExit),
            privacy_budget: DEFAULT_MIN_ANONYMITY_SET,
            anonymity_set: DEFAULT_MIN_ANONYMITY_SET,
            epoch: 0,
            sequence: 0,
        }
    }

    pub fn with_contract(mut self, contract_commitment: &str) -> Self {
        self.contract_commitment = contract_commitment.to_string();
        self.queue_class = QueueClass::from_lane(self.lane, self.low_fee_requested);
        self
    }

    pub fn with_fee_cap(mut self, fee_cap_units: u64, offered_fee_units: u64) -> Self {
        self.fee_cap_units = fee_cap_units;
        self.offered_fee_units = offered_fee_units;
        self
    }

    pub fn with_weight(mut self, weight: u64) -> Self {
        self.estimated_weight = weight;
        self
    }

    pub fn with_prover_jobs(mut self, jobs: u64) -> Self {
        self.estimated_prover_jobs = jobs;
        self
    }

    pub fn with_witness(mut self, witness_root: &str, bytes: u64) -> Self {
        self.witness_root = witness_root.to_string();
        self.estimated_witness_bytes = bytes;
        self
    }

    pub fn with_low_fee(mut self) -> Self {
        self.low_fee_requested = true;
        self.queue_class = QueueClass::from_lane(self.lane, true);
        self
    }

    pub fn with_emergency(mut self) -> Self {
        self.emergency = true;
        self.queue_class = QueueClass::Emergency;
        self
    }

    pub fn with_privacy(mut self, privacy_budget: u64, anonymity_set: u64) -> Self {
        self.privacy_budget = privacy_budget;
        self.anonymity_set = anonymity_set;
        self
    }

    pub fn with_epoch_sequence(mut self, epoch: u64, sequence: u64) -> Self {
        self.epoch = epoch;
        self.sequence = sequence;
        self
    }

    pub fn malformed(&self) -> bool {
        self.request_id.is_empty()
            || self.account_bucket.is_empty()
            || self.payload_commitment.is_empty()
            || self.nullifier_commitment.is_empty()
            || self.estimated_weight == 0
    }

    pub fn commitment_root(&self) -> String {
        stable_hash_hex(
            RECORD_DOMAIN,
            &json!({
                "request_id": self.request_id,
                "account_bucket": self.account_bucket,
                "lane": self.lane.as_str(),
                "payload_commitment": self.payload_commitment,
                "nullifier_commitment": self.nullifier_commitment,
                "contract_commitment": self.contract_commitment,
                "witness_root": self.witness_root,
                "epoch": self.epoch,
                "sequence": self.sequence,
            }),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "account_bucket": self.account_bucket,
            "lane": self.lane.as_str(),
            "queue_class": self.queue_class.as_str(),
            "payload_commitment": self.payload_commitment,
            "nullifier_commitment": self.nullifier_commitment,
            "contract_commitment": self.contract_commitment,
            "witness_root": self.witness_root,
            "fee_cap_units": self.fee_cap_units,
            "offered_fee_units": self.offered_fee_units,
            "estimated_weight": self.estimated_weight,
            "estimated_prover_jobs": self.estimated_prover_jobs,
            "estimated_witness_bytes": self.estimated_witness_bytes,
            "preconfirmation_requested": self.preconfirmation_requested,
            "low_fee_requested": self.low_fee_requested,
            "emergency": self.emergency,
            "privacy_budget": self.privacy_budget,
            "anonymity_set": self.anonymity_set,
            "epoch": self.epoch,
            "sequence": self.sequence,
            "commitment_root": self.commitment_root(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeQuote {
    pub lane: LaneKind,
    pub base_fee_units: u64,
    pub congestion_fee_units: u64,
    pub pq_fee_units: u64,
    pub prover_fee_units: u64,
    pub witness_fee_units: u64,
    pub total_fee_units: u64,
    pub fee_cap_status: FeeCapStatus,
}

impl FeeQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "base_fee_units": self.base_fee_units,
            "congestion_fee_units": self.congestion_fee_units,
            "pq_fee_units": self.pq_fee_units,
            "prover_fee_units": self.prover_fee_units,
            "witness_fee_units": self.witness_fee_units,
            "total_fee_units": self.total_fee_units,
            "fee_cap_status": self.fee_cap_status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionRecord {
    pub request_id: String,
    pub request_root: String,
    pub lane: LaneKind,
    pub queue_class: QueueClass,
    pub decision: AdmissionDecision,
    pub reason: ReasonCode,
    pub load_level: LoadLevel,
    pub shedding_action: SheddingAction,
    pub fee_quote: FeeQuote,
    pub virtual_finish: u128,
    pub queue_position: u64,
    pub accepted_weight: u64,
    pub epoch: u64,
    pub sequence: u64,
}

impl AdmissionRecord {
    pub fn accepted(&self) -> bool {
        self.decision.accepted()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "request_root": self.request_root,
            "lane": self.lane.as_str(),
            "queue_class": self.queue_class.as_str(),
            "decision": self.decision.as_str(),
            "reason": self.reason.as_str(),
            "load_level": self.load_level.as_str(),
            "shedding_action": self.shedding_action.as_str(),
            "fee_quote": self.fee_quote.public_record(),
            "virtual_finish": self.virtual_finish.to_string(),
            "queue_position": self.queue_position,
            "accepted_weight": self.accepted_weight,
            "epoch": self.epoch,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverBacklogRecord {
    pub epoch: u64,
    pub pending_jobs: u64,
    pub max_jobs: u64,
    pub completed_jobs: u64,
    pub failed_jobs: u64,
    pub pq_jobs: u64,
    pub recursive_jobs: u64,
    pub backlog_bps: u64,
    pub load_level: LoadLevel,
    pub throttled: bool,
}

impl ProverBacklogRecord {
    pub fn new(max_jobs: u64) -> Self {
        Self {
            epoch: 0,
            pending_jobs: 0,
            max_jobs,
            completed_jobs: 0,
            failed_jobs: 0,
            pq_jobs: 0,
            recursive_jobs: 0,
            backlog_bps: 0,
            load_level: LoadLevel::Open,
            throttled: false,
        }
    }

    pub fn observe(
        &mut self,
        pending: u64,
        completed: u64,
        failed: u64,
        pq: u64,
        recursive: u64,
        config: &Config,
    ) {
        self.pending_jobs = pending;
        self.completed_jobs = self.completed_jobs.saturating_add(completed);
        self.failed_jobs = self.failed_jobs.saturating_add(failed);
        self.pq_jobs = pq;
        self.recursive_jobs = recursive;
        self.backlog_bps = pending
            .saturating_mul(MAX_BPS)
            .saturating_div(self.max_jobs.max(1))
            .min(MAX_BPS.saturating_mul(2));
        self.load_level = LoadLevel::from_bps(
            self.backlog_bps,
            config.congestion_warn_bps,
            config.congestion_critical_bps,
            config.congestion_halt_bps,
        );
        self.throttled = !self.load_level.admits_nonessential();
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch": self.epoch,
            "pending_jobs": self.pending_jobs,
            "max_jobs": self.max_jobs,
            "completed_jobs": self.completed_jobs,
            "failed_jobs": self.failed_jobs,
            "pq_jobs": self.pq_jobs,
            "recursive_jobs": self.recursive_jobs,
            "backlog_bps": self.backlog_bps,
            "load_level": self.load_level.as_str(),
            "throttled": self.throttled,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessPrefetchRecord {
    pub epoch: u64,
    pub pending_bytes: u64,
    pub max_bytes: u64,
    pub completed_bytes: u64,
    pub dropped_bytes: u64,
    pub prefetch_bps: u64,
    pub load_level: LoadLevel,
    pub throttled: bool,
    pub encrypted_index_root: String,
}

impl WitnessPrefetchRecord {
    pub fn new(max_bytes: u64) -> Self {
        Self {
            epoch: 0,
            pending_bytes: 0,
            max_bytes,
            completed_bytes: 0,
            dropped_bytes: 0,
            prefetch_bps: 0,
            load_level: LoadLevel::Open,
            throttled: false,
            encrypted_index_root: "genesis".to_string(),
        }
    }

    pub fn observe(
        &mut self,
        pending_bytes: u64,
        completed_bytes: u64,
        dropped_bytes: u64,
        encrypted_index_root: &str,
        config: &Config,
    ) {
        self.pending_bytes = pending_bytes;
        self.completed_bytes = self.completed_bytes.saturating_add(completed_bytes);
        self.dropped_bytes = self.dropped_bytes.saturating_add(dropped_bytes);
        self.encrypted_index_root = encrypted_index_root.to_string();
        self.prefetch_bps = pending_bytes
            .saturating_mul(MAX_BPS)
            .saturating_div(self.max_bytes.max(1))
            .min(MAX_BPS.saturating_mul(2));
        self.load_level = LoadLevel::from_bps(
            self.prefetch_bps,
            config.congestion_warn_bps,
            config.congestion_critical_bps,
            config.congestion_halt_bps,
        );
        self.throttled = matches!(
            self.load_level,
            LoadLevel::Critical | LoadLevel::Shedding | LoadLevel::Halted
        );
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch": self.epoch,
            "pending_bytes": self.pending_bytes,
            "max_bytes": self.max_bytes,
            "completed_bytes": self.completed_bytes,
            "dropped_bytes": self.dropped_bytes,
            "prefetch_bps": self.prefetch_bps,
            "load_level": self.load_level.as_str(),
            "throttled": self.throttled,
            "encrypted_index_root": self.encrypted_index_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractHotSpotRecord {
    pub contract_commitment: String,
    pub bucket: String,
    pub inflight_weight: u64,
    pub call_count: u64,
    pub last_epoch: u64,
    pub hot_spot_class: HotSpotClass,
    pub admitted: u64,
    pub deferred: u64,
    pub shed: u64,
}

impl ContractHotSpotRecord {
    pub fn new(contract_commitment: &str, bucket: &str) -> Self {
        Self {
            contract_commitment: contract_commitment.to_string(),
            bucket: bucket.to_string(),
            inflight_weight: 0,
            call_count: 0,
            last_epoch: 0,
            hot_spot_class: HotSpotClass::Cold,
            admitted: 0,
            deferred: 0,
            shed: 0,
        }
    }

    pub fn observe(&mut self, decision: AdmissionDecision, weight: u64, epoch: u64, cap: u64) {
        self.call_count = self.call_count.saturating_add(1);
        self.last_epoch = epoch;
        match decision {
            AdmissionDecision::Admit
            | AdmissionDecision::AdmitLowFee
            | AdmissionDecision::AdmitEmergency => {
                self.admitted = self.admitted.saturating_add(1);
                self.inflight_weight = self.inflight_weight.saturating_add(weight);
            }
            AdmissionDecision::Defer => self.deferred = self.deferred.saturating_add(1),
            _ => self.shed = self.shed.saturating_add(1),
        }
        self.hot_spot_class = HotSpotClass::from_weight(self.inflight_weight, cap);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "contract_commitment": self.contract_commitment,
            "bucket": self.bucket,
            "inflight_weight": self.inflight_weight,
            "call_count": self.call_count,
            "last_epoch": self.last_epoch,
            "hot_spot_class": self.hot_spot_class.as_str(),
            "admitted": self.admitted,
            "deferred": self.deferred,
            "shed": self.shed,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MempoolFairnessRecord {
    pub account_bucket: String,
    pub accepted_count: u64,
    pub deferred_count: u64,
    pub shed_count: u64,
    pub last_virtual_finish: u128,
    pub fairness_debt: u64,
    pub last_epoch: u64,
}

impl MempoolFairnessRecord {
    pub fn new(account_bucket: &str) -> Self {
        Self {
            account_bucket: account_bucket.to_string(),
            accepted_count: 0,
            deferred_count: 0,
            shed_count: 0,
            last_virtual_finish: 0,
            fairness_debt: 0,
            last_epoch: 0,
        }
    }

    pub fn observe(&mut self, decision: AdmissionDecision, virtual_finish: u128, epoch: u64) {
        self.last_epoch = epoch;
        match decision {
            AdmissionDecision::Admit
            | AdmissionDecision::AdmitLowFee
            | AdmissionDecision::AdmitEmergency => {
                self.accepted_count = self.accepted_count.saturating_add(1);
                self.last_virtual_finish = virtual_finish;
                self.fairness_debt = self.fairness_debt.saturating_sub(1);
            }
            AdmissionDecision::Defer => {
                self.deferred_count = self.deferred_count.saturating_add(1);
                self.fairness_debt = self.fairness_debt.saturating_add(1);
            }
            _ => {
                self.shed_count = self.shed_count.saturating_add(1);
                self.fairness_debt = self.fairness_debt.saturating_add(2);
            }
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "account_bucket": self.account_bucket,
            "accepted_count": self.accepted_count,
            "deferred_count": self.deferred_count,
            "shed_count": self.shed_count,
            "last_virtual_finish": self.last_virtual_finish.to_string(),
            "fairness_debt": self.fairness_debt,
            "last_epoch": self.last_epoch,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeCapRecord {
    pub request_id: String,
    pub account_bucket: String,
    pub lane: LaneKind,
    pub fee_cap_units: u64,
    pub quoted_fee_units: u64,
    pub saved_units: u64,
    pub status: FeeCapStatus,
}

impl FeeCapRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "account_bucket": self.account_bucket,
            "lane": self.lane.as_str(),
            "fee_cap_units": self.fee_cap_units,
            "quoted_fee_units": self.quoted_fee_units,
            "saved_units": self.saved_units,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeLaneRecord {
    pub epoch: u64,
    pub reserved_weight: u64,
    pub used_weight: u64,
    pub admitted_count: u64,
    pub deferred_count: u64,
    pub min_fee_cap_units: u64,
}

impl LowFeeLaneRecord {
    pub fn new(config: &Config) -> Self {
        Self {
            epoch: 0,
            reserved_weight: reserve_weight(config.max_block_weight, config.low_fee_reserve_bps),
            used_weight: 0,
            admitted_count: 0,
            deferred_count: 0,
            min_fee_cap_units: config.min_low_fee_cap_units,
        }
    }

    pub fn reset_epoch(&mut self, epoch: u64, config: &Config) {
        self.epoch = epoch;
        self.reserved_weight = reserve_weight(config.max_block_weight, config.low_fee_reserve_bps);
        self.used_weight = 0;
        self.admitted_count = 0;
        self.deferred_count = 0;
    }

    pub fn remaining_weight(&self) -> u64 {
        self.reserved_weight.saturating_sub(self.used_weight)
    }

    pub fn observe(&mut self, decision: AdmissionDecision, weight: u64) {
        match decision {
            AdmissionDecision::AdmitLowFee => {
                self.admitted_count = self.admitted_count.saturating_add(1);
                self.used_weight = self.used_weight.saturating_add(weight);
            }
            AdmissionDecision::Defer => self.deferred_count = self.deferred_count.saturating_add(1),
            _ => {}
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch": self.epoch,
            "reserved_weight": self.reserved_weight,
            "used_weight": self.used_weight,
            "remaining_weight": self.remaining_weight(),
            "admitted_count": self.admitted_count,
            "deferred_count": self.deferred_count,
            "min_fee_cap_units": self.min_fee_cap_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyAdmissionRecord {
    pub epoch: u64,
    pub mode: EmergencyMode,
    pub reserved_weight: u64,
    pub used_weight: u64,
    pub admitted_count: u64,
    pub rejected_count: u64,
    pub last_reason: ReasonCode,
}

impl EmergencyAdmissionRecord {
    pub fn new(config: &Config) -> Self {
        Self {
            epoch: 0,
            mode: EmergencyMode::Normal,
            reserved_weight: reserve_weight(config.max_block_weight, config.emergency_reserve_bps),
            used_weight: 0,
            admitted_count: 0,
            rejected_count: 0,
            last_reason: ReasonCode::None,
        }
    }

    pub fn reset_epoch(&mut self, epoch: u64, config: &Config) {
        self.epoch = epoch;
        self.reserved_weight =
            reserve_weight(config.max_block_weight, config.emergency_reserve_bps);
        self.used_weight = 0;
        self.admitted_count = 0;
        self.rejected_count = 0;
        self.last_reason = ReasonCode::None;
    }

    pub fn remaining_weight(&self) -> u64 {
        self.reserved_weight.saturating_sub(self.used_weight)
    }

    pub fn observe(&mut self, decision: AdmissionDecision, reason: ReasonCode, weight: u64) {
        self.last_reason = reason;
        match decision {
            AdmissionDecision::AdmitEmergency => {
                self.admitted_count = self.admitted_count.saturating_add(1);
                self.used_weight = self.used_weight.saturating_add(weight);
            }
            AdmissionDecision::Shed
            | AdmissionDecision::RejectFeeCap
            | AdmissionDecision::RejectPrivacyBudget
            | AdmissionDecision::RejectHotSpot
            | AdmissionDecision::RejectDuplicate
            | AdmissionDecision::RejectMalformed => {
                self.rejected_count = self.rejected_count.saturating_add(1)
            }
            _ => {}
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch": self.epoch,
            "mode": self.mode.as_str(),
            "reserved_weight": self.reserved_weight,
            "used_weight": self.used_weight,
            "remaining_weight": self.remaining_weight(),
            "admitted_count": self.admitted_count,
            "rejected_count": self.rejected_count,
            "last_reason": self.last_reason.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueTelemetryBucket {
    pub bucket_id: String,
    pub queue_class: QueueClass,
    pub lane: LaneKind,
    pub telemetry_class: PrivacyTelemetryClass,
    pub count_bucket: u64,
    pub weight_bucket: u64,
    pub fee_bucket: u64,
    pub latency_bucket_ms: u64,
    pub anonymity_floor: u64,
    pub commitment_root: String,
}

impl QueueTelemetryBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "queue_class": self.queue_class.as_str(),
            "lane": self.lane.as_str(),
            "telemetry_class": self.telemetry_class.as_str(),
            "count_bucket": self.count_bucket,
            "weight_bucket": self.weight_bucket,
            "fee_bucket": self.fee_bucket,
            "latency_bucket_ms": self.latency_bucket_ms,
            "anonymity_floor": self.anonymity_floor,
            "commitment_root": self.commitment_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueTelemetryRecord {
    pub epoch: u64,
    pub sequence: u64,
    pub telemetry_class: PrivacyTelemetryClass,
    pub bucket_width: u64,
    pub min_anonymity_set: u64,
    pub buckets: Vec<QueueTelemetryBucket>,
    pub suppressed_buckets: u64,
    pub telemetry_root: String,
}

impl QueueTelemetryRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "epoch": self.epoch,
            "sequence": self.sequence,
            "telemetry_class": self.telemetry_class.as_str(),
            "bucket_width": self.bucket_width,
            "min_anonymity_set": self.min_anonymity_set,
            "buckets": self.buckets.iter().map(QueueTelemetryBucket::public_record).collect::<Vec<_>>(),
            "suppressed_buckets": self.suppressed_buckets,
            "telemetry_root": self.telemetry_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SheddingPolicyRecord {
    pub epoch: u64,
    pub global_load_level: LoadLevel,
    pub selected_action: SheddingAction,
    pub reason: ReasonCode,
    pub low_fee_reserve_weight: u64,
    pub emergency_reserve_weight: u64,
    pub preconfirmation_admission_bps: u64,
    pub prover_admission_bps: u64,
    pub witness_admission_bps: u64,
    pub contract_admission_bps: u64,
}

impl SheddingPolicyRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "epoch": self.epoch,
            "global_load_level": self.global_load_level.as_str(),
            "selected_action": self.selected_action.as_str(),
            "reason": self.reason.as_str(),
            "low_fee_reserve_weight": self.low_fee_reserve_weight,
            "emergency_reserve_weight": self.emergency_reserve_weight,
            "preconfirmation_admission_bps": self.preconfirmation_admission_bps,
            "prover_admission_bps": self.prover_admission_bps,
            "witness_admission_bps": self.witness_admission_bps,
            "contract_admission_bps": self.contract_admission_bps,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchItem {
    pub request_id: String,
    pub request_root: String,
    pub lane: LaneKind,
    pub queue_class: QueueClass,
    pub weight: u64,
    pub fee_units: u64,
    pub virtual_finish: u128,
}

impl BatchItem {
    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "request_root": self.request_root,
            "lane": self.lane.as_str(),
            "queue_class": self.queue_class.as_str(),
            "weight": self.weight,
            "fee_units": self.fee_units,
            "virtual_finish": self.virtual_finish.to_string(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchPlan {
    pub epoch: u64,
    pub sequence: u64,
    pub max_weight: u64,
    pub planned_weight: u64,
    pub low_fee_weight: u64,
    pub emergency_weight: u64,
    pub items: Vec<BatchItem>,
    pub deferred_request_ids: Vec<String>,
    pub plan_root: String,
}

impl BatchPlan {
    pub fn empty(epoch: u64, sequence: u64, max_weight: u64) -> Self {
        let mut plan = Self {
            epoch,
            sequence,
            max_weight,
            planned_weight: 0,
            low_fee_weight: 0,
            emergency_weight: 0,
            items: Vec::new(),
            deferred_request_ids: Vec::new(),
            plan_root: String::new(),
        };
        plan.plan_root = stable_hash_hex(RECORD_DOMAIN, &plan.public_record_without_root());
        plan
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "epoch": self.epoch,
            "sequence": self.sequence,
            "max_weight": self.max_weight,
            "planned_weight": self.planned_weight,
            "low_fee_weight": self.low_fee_weight,
            "emergency_weight": self.emergency_weight,
            "items": self.items.iter().map(BatchItem::public_record).collect::<Vec<_>>(),
            "deferred_request_ids": self.deferred_request_ids,
        })
    }

    pub fn public_record(&self) -> Value {
        value_with_root(
            self.public_record_without_root(),
            "plan_root",
            self.plan_root.clone(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct QueuedRequest {
    request: ExecutionRequest,
    admission: AdmissionRecord,
}

impl QueuedRequest {
    fn public_record(&self) -> Value {
        json!({
            "request": self.request.public_record(),
            "admission": self.admission.public_record(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub epoch: u64,
    pub sequence: u64,
    pub lanes: BTreeMap<LaneKind, LaneState>,
    pub queues: BTreeMap<QueueClass, VecDeque<String>>,
    pub accepted_requests: BTreeMap<String, ExecutionRequest>,
    pub accepted_admissions: BTreeMap<String, AdmissionRecord>,
    pub recent_admissions: Vec<AdmissionRecord>,
    pub seen_nullifiers: BTreeSet<String>,
    pub prover_backlog: ProverBacklogRecord,
    pub witness_prefetch: WitnessPrefetchRecord,
    pub hotspots: BTreeMap<String, ContractHotSpotRecord>,
    pub fairness: BTreeMap<String, MempoolFairnessRecord>,
    pub fee_caps: Vec<FeeCapRecord>,
    pub low_fee_lane: LowFeeLaneRecord,
    pub emergency_admission: EmergencyAdmissionRecord,
    pub telemetry: Vec<QueueTelemetryRecord>,
    pub policy: SheddingPolicyRecord,
    pub last_batch_plan: BatchPlan,
    pub counters: Counters,
}

impl State {
    pub fn new(config: Config) -> Self {
        let safe_config = if config.validate().is_ok() {
            config
        } else {
            Config::default()
        };
        let mut lanes = BTreeMap::new();
        for lane in LaneKind::all() {
            lanes.insert(lane, LaneState::new(lane));
        }
        let mut queues = BTreeMap::new();
        for queue_class in QueueClass::all() {
            queues.insert(queue_class, VecDeque::new());
        }
        let low_fee_lane = LowFeeLaneRecord::new(&safe_config);
        let emergency_admission = EmergencyAdmissionRecord::new(&safe_config);
        let policy = SheddingPolicyRecord {
            epoch: 0,
            global_load_level: LoadLevel::Open,
            selected_action: SheddingAction::None,
            reason: ReasonCode::None,
            low_fee_reserve_weight: low_fee_lane.reserved_weight,
            emergency_reserve_weight: emergency_admission.reserved_weight,
            preconfirmation_admission_bps: MAX_BPS,
            prover_admission_bps: MAX_BPS,
            witness_admission_bps: MAX_BPS,
            contract_admission_bps: MAX_BPS,
        };
        Self {
            prover_backlog: ProverBacklogRecord::new(safe_config.max_prover_jobs),
            witness_prefetch: WitnessPrefetchRecord::new(safe_config.max_witness_prefetch_bytes),
            low_fee_lane,
            emergency_admission,
            policy,
            last_batch_plan: BatchPlan::empty(0, 0, safe_config.max_block_weight),
            config: safe_config,
            epoch: 0,
            sequence: 0,
            lanes,
            queues,
            accepted_requests: BTreeMap::new(),
            accepted_admissions: BTreeMap::new(),
            recent_admissions: Vec::new(),
            seen_nullifiers: BTreeSet::new(),
            hotspots: BTreeMap::new(),
            fairness: BTreeMap::new(),
            fee_caps: Vec::new(),
            telemetry: Vec::new(),
            counters: Counters::default(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        state.install_default_hotspots();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::new(Config::demo());
        state.install_default_hotspots();
        let request_a = ExecutionRequest::new(
            "demo-transfer-0001",
            "acct-bucket-a",
            LaneKind::MoneroShieldedTransfer,
            "payload:demo-transfer-0001",
            "nullifier:demo-transfer-0001",
        )
        .with_fee_cap(2_000, 500)
        .with_privacy(64, 96)
        .with_epoch_sequence(0, 1);
        let request_b = ExecutionRequest::new(
            "demo-swap-0002",
            "acct-bucket-b",
            LaneKind::PrivateSwap,
            "payload:demo-swap-0002",
            "nullifier:demo-swap-0002",
        )
        .with_contract("contract:private-swap-router")
        .with_fee_cap(4_000, 900)
        .with_weight(18_000)
        .with_prover_jobs(8)
        .with_privacy(80, 128)
        .with_epoch_sequence(0, 2);
        let request_c = ExecutionRequest::new(
            "demo-low-fee-0003",
            "acct-bucket-c",
            LaneKind::LowFeeRescue,
            "payload:demo-low-fee-0003",
            "nullifier:demo-low-fee-0003",
        )
        .with_low_fee()
        .with_fee_cap(600, 300)
        .with_weight(5_000)
        .with_privacy(64, 64)
        .with_epoch_sequence(0, 3);
        let _ = state.submit_request(request_a);
        let _ = state.submit_request(request_b);
        let _ = state.submit_request(request_c);
        state
    }

    fn install_default_hotspots(&mut self) {
        self.hotspots.insert(
            "contract:private-swap-router".to_string(),
            ContractHotSpotRecord::new("contract:private-swap-router", "defi-router"),
        );
        self.hotspots.insert(
            "contract:lending-pool".to_string(),
            ContractHotSpotRecord::new("contract:lending-pool", "defi-lending"),
        );
        self.hotspots.insert(
            "contract:token-launch".to_string(),
            ContractHotSpotRecord::new("contract:token-launch", "token-launch"),
        );
    }

    pub fn quote_fee(&self, request: &ExecutionRequest) -> FeeQuote {
        let lane_load = match self.lanes.get(&request.lane) {
            Some(lane) => lane.load_level,
            None => LoadLevel::Open,
        };
        let congestion_fee_units = self
            .config
            .base_fee_units
            .saturating_mul(lane_load.multiplier_bps().saturating_sub(MAX_BPS))
            .saturating_div(MAX_BPS);
        let pq_fee_units = request
            .estimated_prover_jobs
            .saturating_mul(self.config.pq_surcharge_units);
        let prover_fee_units = request
            .estimated_prover_jobs
            .saturating_mul(self.config.prover_job_price_units);
        let witness_fee_units = request
            .estimated_witness_bytes
            .saturating_div(1024)
            .saturating_mul(self.config.prefetch_byte_price_units);
        let base_fee_units = self
            .config
            .base_fee_units
            .saturating_add(request.offered_fee_units);
        let total_fee_units = base_fee_units
            .saturating_add(congestion_fee_units)
            .saturating_add(pq_fee_units)
            .saturating_add(prover_fee_units)
            .saturating_add(witness_fee_units);
        let fee_cap_status = if request.low_fee_requested
            && request.fee_cap_units >= self.config.min_low_fee_cap_units
        {
            FeeCapStatus::LowFeeCredit
        } else if total_fee_units <= request.fee_cap_units {
            let margin = request.fee_cap_units.saturating_sub(total_fee_units);
            if margin <= self.config.base_fee_units {
                FeeCapStatus::Tight
            } else {
                FeeCapStatus::Satisfied
            }
        } else {
            FeeCapStatus::TooLow
        };
        FeeQuote {
            lane: request.lane,
            base_fee_units,
            congestion_fee_units,
            pq_fee_units,
            prover_fee_units,
            witness_fee_units,
            total_fee_units,
            fee_cap_status,
        }
    }

    pub fn submit_request(&mut self, mut request: ExecutionRequest) -> AdmissionRecord {
        self.sequence = self.sequence.saturating_add(1);
        if request.sequence == 0 {
            request.sequence = self.sequence;
        }
        request.epoch = self.epoch;
        request.queue_class = QueueClass::from_lane(request.lane, request.low_fee_requested);
        let record = self.evaluate_request(&request);
        self.apply_admission(request, record.clone());
        record
    }

    fn evaluate_request(&self, request: &ExecutionRequest) -> AdmissionRecord {
        let fee_quote = self.quote_fee(request);
        let mut decision = AdmissionDecision::Admit;
        let mut reason = ReasonCode::None;
        let lane_state = match self.lanes.get(&request.lane) {
            Some(lane) => lane.clone(),
            None => LaneState::new(request.lane),
        };
        let mut load_level = lane_state.load_level;
        let mut shedding_action = lane_state.shedding_action;

        if request.malformed() {
            decision = AdmissionDecision::RejectMalformed;
            reason = ReasonCode::MalformedCommitment;
        } else if self.seen_nullifiers.contains(&request.nullifier_commitment) {
            decision = AdmissionDecision::RejectDuplicate;
            reason = ReasonCode::DuplicateNullifier;
        } else if request.anonymity_set < self.config.min_anonymity_set
            || request.privacy_budget == 0
        {
            decision = AdmissionDecision::RejectPrivacyBudget;
            reason = ReasonCode::PrivacyTelemetryBudget;
        } else if !self.emergency_admission.mode.allows_lane(request.lane) {
            decision = AdmissionDecision::Shed;
            reason = ReasonCode::EmergencyAdmissionControl;
            shedding_action = SheddingAction::EmergencyOnly;
            load_level = LoadLevel::Shedding;
        } else if matches!(fee_quote.fee_cap_status, FeeCapStatus::TooLow) {
            decision = AdmissionDecision::RejectFeeCap;
            reason = ReasonCode::UserFeeCap;
        } else if request.lane.contract_sensitive() && self.contract_hotspot_rejects(request) {
            decision = AdmissionDecision::RejectHotSpot;
            reason = ReasonCode::ContractHotSpot;
            shedding_action = SheddingAction::CapContractHotSpot;
        } else if self.preconfirmation_rejects(request) {
            decision = if request.emergency {
                AdmissionDecision::AdmitEmergency
            } else {
                AdmissionDecision::Defer
            };
            reason = ReasonCode::PreconfirmationLoad;
            shedding_action = SheddingAction::PreconfirmationThrottle;
        } else if self.prover_backlog_rejects(request) {
            decision = if request.emergency {
                AdmissionDecision::AdmitEmergency
            } else {
                AdmissionDecision::Defer
            };
            reason = ReasonCode::ProverBacklog;
            shedding_action = SheddingAction::ProverQueueBackpressure;
        } else if self.witness_prefetch_rejects(request) {
            decision = if request.emergency {
                AdmissionDecision::AdmitEmergency
            } else {
                AdmissionDecision::Defer
            };
            reason = ReasonCode::WitnessPrefetchPressure;
            shedding_action = SheddingAction::DelayWitness;
        } else if lane_state.load_level == LoadLevel::Halted && !request.emergency {
            decision = AdmissionDecision::Shed;
            reason = ReasonCode::SequencerCongestion;
            shedding_action = SheddingAction::HaltNewAdmission;
        } else if matches!(lane_state.load_level, LoadLevel::Shedding)
            && !request.low_fee_requested
            && !request.emergency
        {
            decision = AdmissionDecision::Defer;
            reason = ReasonCode::SequencerCongestion;
            shedding_action = SheddingAction::LowFeeOnly;
        } else if request.low_fee_requested || matches!(request.lane, LaneKind::LowFeeRescue) {
            if request.estimated_weight
                <= self
                    .low_fee_lane
                    .remaining_weight()
                    .saturating_add(self.config.max_block_weight)
            {
                decision = AdmissionDecision::AdmitLowFee;
                reason = ReasonCode::LowFeeLaneReserve;
            } else {
                decision = AdmissionDecision::Defer;
                reason = ReasonCode::LowFeeLaneReserve;
            }
        } else if request.emergency || matches!(request.lane, LaneKind::EmergencyExit) {
            decision = AdmissionDecision::AdmitEmergency;
            reason = ReasonCode::EmergencyAdmissionControl;
        }

        let virtual_finish = self.virtual_finish(request);
        let queue_position = self
            .queues
            .get(&request.queue_class)
            .map_or(0, |queue| queue.len() as u64);
        AdmissionRecord {
            request_id: request.request_id.clone(),
            request_root: request.commitment_root(),
            lane: request.lane,
            queue_class: request.queue_class,
            decision,
            reason,
            load_level,
            shedding_action,
            fee_quote,
            virtual_finish,
            queue_position,
            accepted_weight: if decision.accepted() {
                request.estimated_weight
            } else {
                0
            },
            epoch: self.epoch,
            sequence: request.sequence,
        }
    }

    fn virtual_finish(&self, request: &ExecutionRequest) -> u128 {
        let current: u128 = self
            .fairness
            .get(&request.account_bucket)
            .map_or(0, |record| record.last_virtual_finish);
        let lane_weight = request.lane.default_weight().max(1) as u128;
        let quantum_adjustment = request.estimated_prover_jobs.saturating_add(1) as u128;
        let size_cost = request.estimated_weight as u128 * MAX_BPS as u128 / lane_weight;
        current
            .saturating_add(size_cost)
            .saturating_add(quantum_adjustment)
            .saturating_add(request.sequence as u128)
    }

    fn preconfirmation_rejects(&self, request: &ExecutionRequest) -> bool {
        request.preconfirmation_requested
            && self.total_inflight_preconfirmations() >= self.config.max_preconfirmation_inflight
            && !request.emergency
    }

    fn prover_backlog_rejects(&self, request: &ExecutionRequest) -> bool {
        request.estimated_prover_jobs > 0
            && self
                .prover_backlog
                .pending_jobs
                .saturating_add(request.estimated_prover_jobs)
                > self.config.max_prover_jobs
            && !request.emergency
    }

    fn witness_prefetch_rejects(&self, request: &ExecutionRequest) -> bool {
        request.estimated_witness_bytes > 0
            && self
                .witness_prefetch
                .pending_bytes
                .saturating_add(request.estimated_witness_bytes)
                > self.config.max_witness_prefetch_bytes
            && !request.emergency
    }

    fn contract_hotspot_rejects(&self, request: &ExecutionRequest) -> bool {
        if request.contract_commitment == "none" {
            return false;
        }
        self.hotspots
            .get(&request.contract_commitment)
            .map_or(false, |hotspot| {
                !hotspot.hot_spot_class.accepts_new_work()
                    || hotspot
                        .inflight_weight
                        .saturating_add(request.estimated_weight)
                        > self.config.max_contract_hotspot_weight
            })
    }

    fn apply_admission(&mut self, request: ExecutionRequest, record: AdmissionRecord) {
        self.counters.observe_decision(record.decision);
        if let Some(lane) = self.lanes.get_mut(&request.lane) {
            lane.observe_decision(record.decision, request.estimated_weight);
            lane.refresh_load(&self.config);
        }
        self.observe_fairness(&request, &record);
        self.observe_fee_cap(&request, &record);
        self.observe_hotspot(&request, &record);
        self.low_fee_lane
            .observe(record.decision, request.estimated_weight);
        if record.decision == AdmissionDecision::AdmitLowFee {
            self.counters.low_fee_reserved_weight = self
                .counters
                .low_fee_reserved_weight
                .saturating_add(request.estimated_weight);
        }
        self.emergency_admission
            .observe(record.decision, record.reason, request.estimated_weight);
        if record.decision == AdmissionDecision::AdmitEmergency {
            self.counters.emergency_reserved_weight = self
                .counters
                .emergency_reserved_weight
                .saturating_add(request.estimated_weight);
        }
        match record.reason {
            ReasonCode::PreconfirmationLoad => {
                self.counters.preconfirmations_throttled =
                    self.counters.preconfirmations_throttled.saturating_add(1)
            }
            ReasonCode::ProverBacklog => {
                self.counters.prover_jobs_throttled =
                    self.counters.prover_jobs_throttled.saturating_add(1)
            }
            ReasonCode::WitnessPrefetchPressure => {
                self.counters.witness_prefetch_throttled =
                    self.counters.witness_prefetch_throttled.saturating_add(1)
            }
            ReasonCode::ContractHotSpot => {
                self.counters.contract_hotspot_throttled =
                    self.counters.contract_hotspot_throttled.saturating_add(1)
            }
            _ => {}
        }
        self.push_recent_admission(record.clone());
        if record.accepted() {
            self.seen_nullifiers
                .insert(request.nullifier_commitment.clone());
            if self.accepted_requests.len() < self.config.max_private_mempool_items {
                if let Some(queue) = self.queues.get_mut(&request.queue_class) {
                    queue.push_back(request.request_id.clone());
                }
                self.accepted_admissions
                    .insert(request.request_id.clone(), record);
                self.accepted_requests
                    .insert(request.request_id.clone(), request);
            } else {
                self.counters.shed = self.counters.shed.saturating_add(1);
            }
        }
        self.refresh_policy();
    }

    fn observe_fairness(&mut self, request: &ExecutionRequest, record: &AdmissionRecord) {
        let entry = self
            .fairness
            .entry(request.account_bucket.clone())
            .or_insert_with(|| MempoolFairnessRecord::new(&request.account_bucket));
        entry.observe(record.decision, record.virtual_finish, self.epoch);
    }

    fn observe_fee_cap(&mut self, request: &ExecutionRequest, record: &AdmissionRecord) {
        let saved_units = request
            .fee_cap_units
            .saturating_sub(record.fee_quote.total_fee_units);
        if saved_units > 0 {
            self.counters.fee_cap_saves = self.counters.fee_cap_saves.saturating_add(saved_units);
        }
        self.fee_caps.push(FeeCapRecord {
            request_id: request.request_id.clone(),
            account_bucket: request.account_bucket.clone(),
            lane: request.lane,
            fee_cap_units: request.fee_cap_units,
            quoted_fee_units: record.fee_quote.total_fee_units,
            saved_units,
            status: record.fee_quote.fee_cap_status,
        });
        trim_vec_front(&mut self.fee_caps, self.config.max_recent_records);
    }

    fn observe_hotspot(&mut self, request: &ExecutionRequest, record: &AdmissionRecord) {
        if request.contract_commitment == "none" {
            return;
        }
        let bucket = contract_bucket(&request.contract_commitment);
        let entry = self
            .hotspots
            .entry(request.contract_commitment.clone())
            .or_insert_with(|| ContractHotSpotRecord::new(&request.contract_commitment, &bucket));
        entry.observe(
            record.decision,
            request.estimated_weight,
            self.epoch,
            self.config.max_contract_hotspot_weight,
        );
        if self.hotspots.len() > self.config.max_hotspots {
            let key = self
                .hotspots
                .iter()
                .min_by_key(|(_, record)| (record.last_epoch, record.inflight_weight))
                .map(|(key, _)| key.clone());
            if let Some(remove_key) = key {
                let _ = self.hotspots.remove(&remove_key);
            }
        }
    }

    fn push_recent_admission(&mut self, record: AdmissionRecord) {
        self.recent_admissions.push(record);
        trim_vec_front(&mut self.recent_admissions, self.config.max_recent_records);
    }

    pub fn observe_prover_backlog(
        &mut self,
        pending: u64,
        completed: u64,
        failed: u64,
        pq: u64,
        recursive: u64,
    ) {
        self.prover_backlog.epoch = self.epoch;
        self.prover_backlog
            .observe(pending, completed, failed, pq, recursive, &self.config);
        self.refresh_policy();
    }

    pub fn observe_witness_prefetch(
        &mut self,
        pending_bytes: u64,
        completed_bytes: u64,
        dropped_bytes: u64,
        encrypted_index_root: &str,
    ) {
        self.witness_prefetch.epoch = self.epoch;
        self.witness_prefetch.observe(
            pending_bytes,
            completed_bytes,
            dropped_bytes,
            encrypted_index_root,
            &self.config,
        );
        self.refresh_policy();
    }

    pub fn set_emergency_mode(&mut self, mode: EmergencyMode) {
        self.emergency_admission.mode = mode;
        self.refresh_policy();
    }

    pub fn tick_epoch(&mut self) {
        self.epoch = self.epoch.saturating_add(1);
        self.low_fee_lane.reset_epoch(self.epoch, &self.config);
        self.emergency_admission
            .reset_epoch(self.epoch, &self.config);
        for lane in self.lanes.values_mut() {
            lane.inflight_weight = lane.inflight_weight.saturating_mul(7).saturating_div(10);
            lane.planned_weight = 0;
            lane.refresh_load(&self.config);
        }
        for hotspot in self.hotspots.values_mut() {
            hotspot.inflight_weight = hotspot.inflight_weight.saturating_mul(6).saturating_div(10);
            hotspot.hot_spot_class = HotSpotClass::from_weight(
                hotspot.inflight_weight,
                self.config.max_contract_hotspot_weight,
            );
        }
        self.refresh_policy();
    }

    pub fn plan_block(&mut self) -> BatchPlan {
        let mut plan = BatchPlan::empty(self.epoch, self.sequence, self.config.max_block_weight);
        let order = vec![
            QueueClass::Emergency,
            QueueClass::LowFee,
            QueueClass::FastPrivate,
            QueueClass::Contract,
            QueueClass::StandardPrivate,
            QueueClass::Prover,
            QueueClass::Witness,
            QueueClass::Bulk,
        ];
        for queue_class in order {
            self.drain_queue_class(queue_class, &mut plan);
        }
        plan.plan_root = stable_hash_hex(RECORD_DOMAIN, &plan.public_record_without_root());
        self.counters.planned_batches = self.counters.planned_batches.saturating_add(1);
        self.counters.planned_items = self
            .counters
            .planned_items
            .saturating_add(plan.items.len() as u64);
        self.counters.planned_weight = self
            .counters
            .planned_weight
            .saturating_add(plan.planned_weight);
        self.last_batch_plan = plan.clone();
        plan
    }

    fn drain_queue_class(&mut self, queue_class: QueueClass, plan: &mut BatchPlan) {
        let mut retained = VecDeque::new();
        let mut existing = match self.queues.remove(&queue_class) {
            Some(queue) => queue,
            None => VecDeque::new(),
        };
        while let Some(request_id) = existing.pop_front() {
            let maybe_request = self.accepted_requests.get(&request_id).cloned();
            let maybe_admission = self.accepted_admissions.get(&request_id).cloned();
            if let (Some(request), Some(admission)) = (maybe_request, maybe_admission) {
                if plan.planned_weight.saturating_add(request.estimated_weight) <= plan.max_weight
                    && self.policy_allows_queue(queue_class)
                {
                    plan.planned_weight =
                        plan.planned_weight.saturating_add(request.estimated_weight);
                    if queue_class == QueueClass::LowFee {
                        plan.low_fee_weight =
                            plan.low_fee_weight.saturating_add(request.estimated_weight);
                    }
                    if queue_class == QueueClass::Emergency {
                        plan.emergency_weight = plan
                            .emergency_weight
                            .saturating_add(request.estimated_weight);
                    }
                    plan.items.push(BatchItem {
                        request_id: request.request_id.clone(),
                        request_root: admission.request_root.clone(),
                        lane: request.lane,
                        queue_class,
                        weight: request.estimated_weight,
                        fee_units: admission.fee_quote.total_fee_units,
                        virtual_finish: admission.virtual_finish,
                    });
                    if let Some(lane) = self.lanes.get_mut(&request.lane) {
                        lane.planned_weight =
                            lane.planned_weight.saturating_add(request.estimated_weight);
                        lane.inflight_weight = lane
                            .inflight_weight
                            .saturating_sub(request.estimated_weight);
                        lane.refresh_load(&self.config);
                    }
                    let _ = self.accepted_requests.remove(&request_id);
                    let _ = self.accepted_admissions.remove(&request_id);
                } else {
                    plan.deferred_request_ids.push(request_id.clone());
                    retained.push_back(request_id);
                }
            }
        }
        self.queues.insert(queue_class, retained);
    }

    fn policy_allows_queue(&self, queue_class: QueueClass) -> bool {
        match self.policy.selected_action {
            SheddingAction::None => true,
            SheddingAction::DelayBulk => queue_class != QueueClass::Bulk,
            SheddingAction::DelayWitness => queue_class != QueueClass::Witness,
            SheddingAction::CapContractHotSpot => true,
            SheddingAction::ProverQueueBackpressure => queue_class != QueueClass::Prover,
            SheddingAction::PreconfirmationThrottle => true,
            SheddingAction::LowFeeOnly => {
                matches!(
                    queue_class,
                    QueueClass::LowFee | QueueClass::Emergency | QueueClass::FastPrivate
                )
            }
            SheddingAction::EmergencyOnly => queue_class == QueueClass::Emergency,
            SheddingAction::HaltNewAdmission => queue_class == QueueClass::Emergency,
        }
    }

    pub fn export_private_queue_telemetry(
        &mut self,
        telemetry_class: PrivacyTelemetryClass,
    ) -> QueueTelemetryRecord {
        let mut raw: BTreeMap<(QueueClass, LaneKind), (u64, u64, u64)> = BTreeMap::new();
        for request in self.accepted_requests.values() {
            let key = (request.queue_class, request.lane);
            let entry = raw.entry(key).or_insert((0, 0, 0));
            entry.0 = entry.0.saturating_add(1);
            entry.1 = entry.1.saturating_add(request.estimated_weight);
            entry.2 = entry.2.saturating_add(request.offered_fee_units);
        }
        let mut buckets = Vec::new();
        let mut suppressed_buckets = 0_u64;
        for ((queue_class, lane), (count, weight, fee)) in raw {
            if count < self.config.min_anonymity_set
                && telemetry_class != PrivacyTelemetryClass::PublicRootOnly
            {
                suppressed_buckets = suppressed_buckets.saturating_add(1);
                continue;
            }
            let count_bucket = coarse_bucket(count, self.config.telemetry_bucket_width);
            let weight_bucket = coarse_bucket(
                weight,
                self.config.telemetry_bucket_width.saturating_mul(1024),
            );
            let fee_bucket =
                coarse_bucket(fee, self.config.telemetry_bucket_width.saturating_mul(10));
            let latency_bucket_ms =
                coarse_bucket(lane.default_sla_ms(), self.config.target_block_ms.max(1));
            let bucket_id = stable_hash_hex(
                TELEMETRY_DOMAIN,
                &json!({
                    "epoch": self.epoch,
                    "queue_class": queue_class.as_str(),
                    "lane": lane.as_str(),
                    "count_bucket": count_bucket,
                    "weight_bucket": weight_bucket,
                    "fee_bucket": fee_bucket,
                }),
            );
            let commitment_root = stable_hash_hex(
                TELEMETRY_DOMAIN,
                &json!({
                    "bucket_id": bucket_id,
                    "telemetry_class": telemetry_class.as_str(),
                    "anonymity_floor": self.config.min_anonymity_set,
                }),
            );
            buckets.push(QueueTelemetryBucket {
                bucket_id,
                queue_class,
                lane,
                telemetry_class,
                count_bucket,
                weight_bucket,
                fee_bucket,
                latency_bucket_ms,
                anonymity_floor: self.config.min_anonymity_set,
                commitment_root,
            });
        }
        if buckets.len() > self.config.max_telemetry_buckets {
            buckets.truncate(self.config.max_telemetry_buckets);
        }
        let telemetry_root = stable_hash_hex(
            TELEMETRY_DOMAIN,
            &json!({
                "epoch": self.epoch,
                "sequence": self.sequence,
                "buckets": buckets.iter().map(QueueTelemetryBucket::public_record).collect::<Vec<_>>(),
                "suppressed_buckets": suppressed_buckets,
            }),
        );
        let record = QueueTelemetryRecord {
            epoch: self.epoch,
            sequence: self.sequence,
            telemetry_class,
            bucket_width: self.config.telemetry_bucket_width,
            min_anonymity_set: self.config.min_anonymity_set,
            buckets,
            suppressed_buckets,
            telemetry_root,
        };
        self.telemetry.push(record.clone());
        trim_vec_front(&mut self.telemetry, self.config.max_recent_records);
        self.counters.telemetry_exports = self.counters.telemetry_exports.saturating_add(1);
        record
    }

    fn refresh_policy(&mut self) {
        for lane in self.lanes.values_mut() {
            lane.refresh_load(&self.config);
        }
        let sequencer_bps = self
            .global_inflight_weight()
            .saturating_mul(MAX_BPS)
            .saturating_div(self.config.max_block_weight.max(1));
        let mut global_load = LoadLevel::from_bps(
            sequencer_bps,
            self.config.congestion_warn_bps,
            self.config.congestion_critical_bps,
            self.config.congestion_halt_bps,
        );
        if self.prover_backlog.load_level > global_load {
            global_load = self.prover_backlog.load_level;
        }
        if self.witness_prefetch.load_level > global_load {
            global_load = self.witness_prefetch.load_level;
        }
        let mut selected_action = match global_load {
            LoadLevel::Open | LoadLevel::Warm => SheddingAction::None,
            LoadLevel::Congested => SheddingAction::DelayBulk,
            LoadLevel::Critical => SheddingAction::PreconfirmationThrottle,
            LoadLevel::Shedding => SheddingAction::LowFeeOnly,
            LoadLevel::Halted => SheddingAction::HaltNewAdmission,
        };
        let mut reason = match global_load {
            LoadLevel::Open | LoadLevel::Warm => ReasonCode::None,
            _ => ReasonCode::SequencerCongestion,
        };
        if self.prover_backlog.throttled {
            selected_action = SheddingAction::ProverQueueBackpressure;
            reason = ReasonCode::ProverBacklog;
        }
        if self.witness_prefetch.throttled && selected_action < SheddingAction::LowFeeOnly {
            selected_action = SheddingAction::DelayWitness;
            reason = ReasonCode::WitnessPrefetchPressure;
        }
        if matches!(
            self.emergency_admission.mode,
            EmergencyMode::ExitOnly | EmergencyMode::SequencerRecovery | EmergencyMode::FullHalt
        ) {
            selected_action = SheddingAction::EmergencyOnly;
            reason = ReasonCode::EmergencyAdmissionControl;
            global_load = LoadLevel::Shedding;
        }
        self.policy = SheddingPolicyRecord {
            epoch: self.epoch,
            global_load_level: global_load,
            selected_action,
            reason,
            low_fee_reserve_weight: self.low_fee_lane.reserved_weight,
            emergency_reserve_weight: self.emergency_admission.reserved_weight,
            preconfirmation_admission_bps: admission_bps_for(
                global_load,
                ReasonCode::PreconfirmationLoad,
            ),
            prover_admission_bps: admission_bps_for(
                self.prover_backlog.load_level,
                ReasonCode::ProverBacklog,
            ),
            witness_admission_bps: admission_bps_for(
                self.witness_prefetch.load_level,
                ReasonCode::WitnessPrefetchPressure,
            ),
            contract_admission_bps: admission_bps_for(global_load, ReasonCode::ContractHotSpot),
        };
    }

    pub fn total_inflight_preconfirmations(&self) -> u64 {
        self.accepted_requests
            .values()
            .filter(|request| request.preconfirmation_requested)
            .count() as u64
    }

    pub fn global_inflight_weight(&self) -> u64 {
        self.lanes
            .values()
            .fold(0_u64, |acc, lane| acc.saturating_add(lane.inflight_weight))
    }

    pub fn queue_depth(&self, queue_class: QueueClass) -> u64 {
        self.queues
            .get(&queue_class)
            .map_or(0, |queue| queue.len() as u64)
    }

    pub fn roots(&self) -> Roots {
        let config_root = stable_hash_hex(ROOT_DOMAIN, &self.config.public_record());
        let lane_root = stable_hash_hex(
            ROOT_DOMAIN,
            &json!(self
                .lanes
                .values()
                .map(LaneState::public_record)
                .collect::<Vec<_>>()),
        );
        let queue_root = stable_hash_hex(ROOT_DOMAIN, &self.queue_public_record());
        let request_root = stable_hash_hex(
            ROOT_DOMAIN,
            &json!(self
                .accepted_requests
                .values()
                .map(ExecutionRequest::public_record)
                .collect::<Vec<_>>()),
        );
        let admission_root = stable_hash_hex(
            ROOT_DOMAIN,
            &json!(self
                .recent_admissions
                .iter()
                .map(AdmissionRecord::public_record)
                .collect::<Vec<_>>()),
        );
        let prover_root = stable_hash_hex(ROOT_DOMAIN, &self.prover_backlog.public_record());
        let witness_root = stable_hash_hex(ROOT_DOMAIN, &self.witness_prefetch.public_record());
        let hotspot_root = stable_hash_hex(
            ROOT_DOMAIN,
            &json!(self
                .hotspots
                .values()
                .map(ContractHotSpotRecord::public_record)
                .collect::<Vec<_>>()),
        );
        let fee_cap_root = stable_hash_hex(
            ROOT_DOMAIN,
            &json!(self
                .fee_caps
                .iter()
                .map(FeeCapRecord::public_record)
                .collect::<Vec<_>>()),
        );
        let fairness_root = stable_hash_hex(
            ROOT_DOMAIN,
            &json!(self
                .fairness
                .values()
                .map(MempoolFairnessRecord::public_record)
                .collect::<Vec<_>>()),
        );
        let telemetry_root = stable_hash_hex(
            ROOT_DOMAIN,
            &json!(self
                .telemetry
                .iter()
                .map(QueueTelemetryRecord::public_record)
                .collect::<Vec<_>>()),
        );
        let emergency_root =
            stable_hash_hex(ROOT_DOMAIN, &self.emergency_admission.public_record());
        let counters_root = stable_hash_hex(ROOT_DOMAIN, &self.counters.public_record());
        let public_record_without_roots = self.public_record_without_roots();
        let public_record_root = stable_hash_hex(ROOT_DOMAIN, &public_record_without_roots);
        let state_root = stable_hash_hex(
            ROOT_DOMAIN,
            &json!({
                "config_root": config_root,
                "lane_root": lane_root,
                "queue_root": queue_root,
                "request_root": request_root,
                "admission_root": admission_root,
                "prover_root": prover_root,
                "witness_root": witness_root,
                "hotspot_root": hotspot_root,
                "fee_cap_root": fee_cap_root,
                "fairness_root": fairness_root,
                "telemetry_root": telemetry_root,
                "emergency_root": emergency_root,
                "counters_root": counters_root,
                "public_record_root": public_record_root,
            }),
        );
        Roots {
            config_root,
            lane_root,
            queue_root,
            request_root,
            admission_root,
            prover_root,
            witness_root,
            hotspot_root,
            fee_cap_root,
            fairness_root,
            telemetry_root,
            emergency_root,
            counters_root,
            public_record_root,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn queue_public_record(&self) -> Value {
        let mut queues = Vec::new();
        for (queue_class, queue) in &self.queues {
            queues.push(json!({
                "queue_class": queue_class.as_str(),
                "depth": queue.len(),
                "request_ids": queue.iter().cloned().collect::<Vec<_>>(),
            }));
        }
        json!(queues)
    }

    pub fn public_record_without_roots(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "module_protocol_version": MODULE_PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "epoch": self.epoch,
            "sequence": self.sequence,
            "config": self.config.public_record(),
            "lanes": self.lanes.values().map(LaneState::public_record).collect::<Vec<_>>(),
            "queues": self.queue_public_record(),
            "accepted_request_count": self.accepted_requests.len(),
            "recent_admissions": self.recent_admissions.iter().map(AdmissionRecord::public_record).collect::<Vec<_>>(),
            "prover_backlog": self.prover_backlog.public_record(),
            "witness_prefetch": self.witness_prefetch.public_record(),
            "hotspots": self.hotspots.values().map(ContractHotSpotRecord::public_record).collect::<Vec<_>>(),
            "fairness": self.fairness.values().map(MempoolFairnessRecord::public_record).collect::<Vec<_>>(),
            "fee_caps": self.fee_caps.iter().map(FeeCapRecord::public_record).collect::<Vec<_>>(),
            "low_fee_lane": self.low_fee_lane.public_record(),
            "emergency_admission": self.emergency_admission.public_record(),
            "telemetry": self.telemetry.iter().map(QueueTelemetryRecord::public_record).collect::<Vec<_>>(),
            "policy": self.policy.public_record(),
            "last_batch_plan": self.last_batch_plan.public_record(),
            "counters": self.counters.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        value_with_root(
            value_with_root(
                self.public_record_without_roots(),
                "roots",
                roots.public_record(),
            ),
            "state_root",
            roots.state_root,
        )
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn reserve_weight(max_weight: u64, reserve_bps: u64) -> u64 {
    max_weight.saturating_mul(reserve_bps.min(MAX_BPS)) / MAX_BPS
}

fn coarse_bucket(value: u64, width: u64) -> u64 {
    if width == 0 {
        value
    } else {
        value.saturating_add(width.saturating_sub(1)) / width * width
    }
}

fn contract_bucket(contract_commitment: &str) -> String {
    let root = stable_hash_hex(
        RECORD_DOMAIN,
        &json!({ "contract_commitment": contract_commitment }),
    );
    root.chars().take(16).collect()
}

fn admission_bps_for(load: LoadLevel, _reason: ReasonCode) -> u64 {
    match load {
        LoadLevel::Open => MAX_BPS,
        LoadLevel::Warm => 9_000,
        LoadLevel::Congested => 7_500,
        LoadLevel::Critical => 5_000,
        LoadLevel::Shedding => 2_500,
        LoadLevel::Halted => 0,
    }
}

fn trim_vec_front<T>(items: &mut Vec<T>, max_len: usize) {
    if items.len() > max_len {
        let drop_count = items.len().saturating_sub(max_len);
        items.drain(0..drop_count);
    }
}

fn value_with_root<V: Into<Value>>(mut value: Value, key: &str, root: V) -> Value {
    let root_value = root.into();
    if let Value::Object(ref mut object) = value {
        object.insert(key.to_string(), root_value);
        value
    } else {
        let mut object = serde_json::Map::new();
        object.insert("value".to_string(), value);
        object.insert(key.to_string(), root_value);
        Value::Object(object)
    }
}

fn stable_hash_hex(domain: &str, value: &Value) -> String {
    let canonical = canonical_json(value);
    let mut out = String::new();
    for counter in 0_u64..4 {
        let mut hasher = DefaultHasher::new();
        domain.hash(&mut hasher);
        counter.hash(&mut hasher);
        canonical.hash(&mut hasher);
        let word = hasher.finish();
        out.push_str(&format!("{word:016x}"));
    }
    out
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(v) => {
            if *v {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Value::Number(v) => v.to_string(),
        Value::String(v) => {
            let mut escaped = String::new();
            escaped.push('"');
            for ch in v.chars() {
                match ch {
                    '"' => escaped.push_str("\\\""),
                    '\\' => escaped.push_str("\\\\"),
                    '\n' => escaped.push_str("\\n"),
                    '\r' => escaped.push_str("\\r"),
                    '\t' => escaped.push_str("\\t"),
                    _ => escaped.push(ch),
                }
            }
            escaped.push('"');
            escaped
        }
        Value::Array(items) => {
            let mut out = String::from("[");
            let mut first = true;
            for item in items {
                if !first {
                    out.push(',');
                }
                first = false;
                out.push_str(&canonical_json(item));
            }
            out.push(']');
            out
        }
        Value::Object(map) => {
            let mut out = String::from("{");
            let mut first = true;
            for (key, item) in map {
                if !first {
                    out.push(',');
                }
                first = false;
                out.push_str(&canonical_json(&Value::String(key.clone())));
                out.push(':');
                out.push_str(&canonical_json(item));
            }
            out.push('}');
            out
        }
    }
}
