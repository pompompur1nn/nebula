use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialBridgeDandelionPacketFountainReorgInsuranceRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-bridge-dandelion-packet-fountain-reorg-insurance-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_BRIDGE_DANDELION_PACKET_FOUNTAIN_REORG_INSURANCE_RUNTIME_PROTOCOL_VERSION:
    &str = PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_DANDELION_PACKET_FOUNTAIN_REORG_INSURANCE_SUITE: &str =
    "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f";
pub const DANDELION_PACKET_FOUNTAIN_REORG_INSURANCE_SUITE: &str =
    "monero-bridge-dandelion-packet-fountain-reorg-insurance-root-v1";
pub const REBATE_SUITE: &str = "dandelion-packet-fountain-reorg-insurance-low-fee-rebate-root-v1";
pub const REDACTION_SUITE: &str =
    "operator-safe-dandelion-packet-fountain-reorg-insurance-redaction-root-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_BRIDGE_ASSET_ID: &str = "xmr-confidential-bridge-note-devnet";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_DANDELION_PACKET_FOUNTAIN_REORG_WINDOW_SLOTS: u64 = 720;
pub const DEFAULT_SIGNAL_WINDOW_SLOTS: u64 = 96;
pub const DEFAULT_MAX_ROUTE_FEE_BPS: u64 = 20;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 8;
pub const DEFAULT_MIN_SOURCE_LIQUIDITY_MICRO_UNITS: u64 = 128_000_000;
pub const DEFAULT_MIN_TARGET_LIQUIDITY_MICRO_UNITS: u64 = 64_000_000;
pub const DEFAULT_MIN_ATTESTATION_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_ATTESTATION_QUORUM_BPS: u64 = 8_500;
pub const DEFAULT_MAX_PUBLIC_REDACTION_BYTES: u64 = 2_048;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_POLICIES: usize = 524_288;
pub const MAX_COHORTS: usize = 1_048_576;
pub const MAX_SIGNALS: usize = 2_097_152;
pub const MAX_ATTESTATIONS: usize = 4_194_304;
pub const MAX_DECISIONS: usize = 2_097_152;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_REDACTION_BUDGETS: usize = 524_288;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const DEVNET_EPOCH: u64 = 8_416;
pub const DEVNET_SLOT: u64 = 421;
pub const DEVNET_L2_HEIGHT: u64 = 3_648_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DandelionPacketFountainReorgScope {
    DepositPacketFountainLane,
    WithdrawalPacketFountainLane,
    FastDandelionPacketFountainReorgRecoveryLane,
    MerchantPaymentPacketFountainLane,
    AtomicSwapPacketFountainLane,
    ReserveMirror,
    EmergencyDandelionPacketFountainReorgInsurance,
    WatchtowerRecovery,
}

impl DandelionPacketFountainReorgScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositPacketFountainLane => "deposit_packet-fountain_lane",
            Self::WithdrawalPacketFountainLane => "withdrawal_packet-fountain_lane",
            Self::FastDandelionPacketFountainReorgRecoveryLane => {
                "fast_dandelion_packet_fountain_reorg_recovery_lane"
            }
            Self::MerchantPaymentPacketFountainLane => "merchant_payment_packet-fountain_lane",
            Self::AtomicSwapPacketFountainLane => "atomic_swap_packet-fountain_lane",
            Self::ReserveMirror => "reserve_mirror",
            Self::EmergencyDandelionPacketFountainReorgInsurance => {
                "emergency_dandelion_packet_fountain_reorg_insurance"
            }
            Self::WatchtowerRecovery => "watchtower_recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Active,
    PacketFountainReorgPathPending,
    DandelionPacketFountainReorgInsuring,
    Quarantined,
    Rotating,
    Paused,
    Settled,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    DandelionPacketFountainReorgLinkagePressure,
    DandelionPacketFountainReorgPathFragmentation,
    DandelionPacketFountainReorgPathSkew,
    DandelionPacketFountainReorgGraphLinkagePressure,
    DandelionPacketFountainReorgTimingCorrelationPressure,
    ReserveMismatch,
    PacketFountainReorgDepthInsuranceClaimPressure,
    WatchtowerEmergency,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalStatus {
    Submitted,
    Attested,
    PacketFountainReorgPathQueued,
    DandelionPacketFountainReorgInsuring,
    Quarantined,
    Settled,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    ConfirmDandelionPacketFountainReorg,
    ConfirmPrivacyRisk,
    RequireDandelionPacketFountainReorgCoverage,
    RequireDandelionPacketFountainReorgCoverageGuard,
    RequireQuarantine,
    ClearFalsePositive,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DandelionPacketFountainReorgAction {
    Observe,
    QueueDandelionPacketFountainReorgInsuranceClaimReview,
    SettleDandelionPacketFountainReorg,
    RotateDandelionPacketFountainReorgInsuranceSettlementCohort,
    QuarantinePacketFountainReorgPath,
    EmergencyPause,
    Release,
    Reject,
    Expire,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub hash_suite: String,
    pub pq_claim_settlement_insurance_suite: String,
    pub dandelion_packet_fountain_reorg_insurance_suite: String,
    pub rebate_suite: String,
    pub redaction_suite: String,
    pub fee_asset_id: String,
    pub bridge_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub dandelion_packet_fountain_reorg_window_slots: u64,
    pub signal_window_slots: u64,
    pub max_claim_settlement_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub min_pre_dandelion_packet_fountain_reorg_reserve_micro_units: u64,
    pub min_dandelion_packet_fountain_reorg_lane_claim_reserve_micro_units: u64,
    pub min_attestation_quorum_bps: u64,
    pub strong_attestation_quorum_bps: u64,
    pub max_public_redaction_bytes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_claim_settlement_insurance_suite: PQ_DANDELION_PACKET_FOUNTAIN_REORG_INSURANCE_SUITE
                .to_string(),
            dandelion_packet_fountain_reorg_insurance_suite:
                DANDELION_PACKET_FOUNTAIN_REORG_INSURANCE_SUITE.to_string(),
            rebate_suite: REBATE_SUITE.to_string(),
            redaction_suite: REDACTION_SUITE.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            bridge_asset_id: DEFAULT_BRIDGE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            dandelion_packet_fountain_reorg_window_slots:
                DEFAULT_DANDELION_PACKET_FOUNTAIN_REORG_WINDOW_SLOTS,
            signal_window_slots: DEFAULT_SIGNAL_WINDOW_SLOTS,
            max_claim_settlement_fee_bps: DEFAULT_MAX_ROUTE_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            min_pre_dandelion_packet_fountain_reorg_reserve_micro_units:
                DEFAULT_MIN_SOURCE_LIQUIDITY_MICRO_UNITS,
            min_dandelion_packet_fountain_reorg_lane_claim_reserve_micro_units:
                DEFAULT_MIN_TARGET_LIQUIDITY_MICRO_UNITS,
            min_attestation_quorum_bps: DEFAULT_MIN_ATTESTATION_QUORUM_BPS,
            strong_attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
            max_public_redaction_bytes: DEFAULT_MAX_PUBLIC_REDACTION_BYTES,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub policies_registered: u64,
    pub cohorts_registered: u64,
    pub signals_submitted: u64,
    pub attestations_recorded: u64,
    pub decisions_published: u64,
    pub dandelion_packet_fountain_reorg_filters_settled: u64,
    pub cohorts_rotated: u64,
    pub claim_reorg_paths_quarantined: u64,
    pub cohorts_released: u64,
    pub rebates_published: u64,
    pub redaction_budgets_published: u64,
    pub operator_summaries_published: u64,
    pub active_signal_count: u64,
    pub live_quarantine_count: u64,
    pub total_privacy_filtered_micro_units: u64,
    pub total_rebate_micro_units: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub policy_root: String,
    pub cohort_root: String,
    pub signal_root: String,
    pub attestation_root: String,
    pub decision_root: String,
    pub rebate_root: String,
    pub redaction_root: String,
    pub operator_summary_root: String,
    pub counters_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DandelionPacketFountainReorgPolicy {
    pub policy_id: String,
    pub scope: DandelionPacketFountainReorgScope,
    pub owner_commitment: String,
    pub policy_commitment_root: String,
    pub claim_source_dandelion_packet_fountain_reorg_set_root: String,
    pub claim_target_dandelion_packet_fountain_reorg_set_root: String,
    pub claim_rotation_allowlist_root: String,
    pub min_privacy_set_size: u64,
    pub min_pre_dandelion_packet_fountain_reorg_reserve_micro_units: u64,
    pub min_dandelion_packet_fountain_reorg_lane_claim_reserve_micro_units: u64,
    pub max_claim_settlement_fee_bps: u64,
    pub min_attestation_quorum_bps: u64,
    pub signal_window_slots: u64,
    pub dandelion_packet_fountain_reorg_window_slots: u64,
    pub active: bool,
    pub redaction_profile: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisterPolicyRequest {
    pub scope: DandelionPacketFountainReorgScope,
    pub owner_commitment: String,
    pub policy_commitment_root: String,
    pub claim_source_dandelion_packet_fountain_reorg_set_root: String,
    pub claim_target_dandelion_packet_fountain_reorg_set_root: String,
    pub claim_rotation_allowlist_root: String,
    pub min_privacy_set_size: u64,
    pub min_pre_dandelion_packet_fountain_reorg_reserve_micro_units: u64,
    pub min_dandelion_packet_fountain_reorg_lane_claim_reserve_micro_units: u64,
    pub max_claim_settlement_fee_bps: u64,
    pub min_attestation_quorum_bps: u64,
    pub signal_window_slots: u64,
    pub dandelion_packet_fountain_reorg_window_slots: u64,
    pub redaction_profile: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DandelionPacketFountainReorgInsuranceCohort {
    pub cohort_id: String,
    pub policy_id: String,
    pub scope: DandelionPacketFountainReorgScope,
    pub status: CohortStatus,
    pub bridge_lane_id: String,
    pub claim_source_dandelion_packet_fountain_reorg_set_root: String,
    pub claim_target_dandelion_packet_fountain_reorg_set_root: String,
    pub output_set_root: String,
    pub decoy_insurance_commitment_root: String,
    pub pre_dandelion_packet_fountain_reorg_reserve_micro_units: u64,
    pub dandelion_packet_fountain_reorg_lane_claim_reserve_micro_units: u64,
    pub privacy_set_size: u64,
    pub claim_settlement_fee_bps: u64,
    pub active_signal_count: u64,
    pub privacy_filter_deadline_slot: u64,
    pub public_hint_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisterCohortRequest {
    pub policy_id: String,
    pub bridge_lane_id: String,
    pub claim_source_dandelion_packet_fountain_reorg_set_root: String,
    pub claim_target_dandelion_packet_fountain_reorg_set_root: String,
    pub output_set_root: String,
    pub decoy_insurance_commitment_root: String,
    pub pre_dandelion_packet_fountain_reorg_reserve_micro_units: u64,
    pub dandelion_packet_fountain_reorg_lane_claim_reserve_micro_units: u64,
    pub privacy_set_size: u64,
    pub claim_settlement_fee_bps: u64,
    pub public_hint_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DandelionPacketFountainReorgSignal {
    pub signal_id: String,
    pub cohort_id: String,
    pub policy_id: String,
    pub kind: SignalKind,
    pub status: SignalStatus,
    pub signal_commitment_root: String,
    pub observed_claim_reorg_path_root: String,
    pub dandelion_packet_fountain_reorg_pressure_root: String,
    pub reporter_commitment: String,
    pub pre_reorg_reserve_delta_micro_units: i128,
    pub packet_fountain_reorg_lane_claim_reserve_delta_micro_units: i128,
    pub privacy_set_size: u64,
    pub packet_fountain_reorg_risk_score_bps: u64,
    pub submitted_at_slot: u64,
    pub expires_at_slot: u64,
    pub attestation_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubmitSignalRequest {
    pub cohort_id: String,
    pub kind: SignalKind,
    pub signal_commitment_root: String,
    pub observed_claim_reorg_path_root: String,
    pub dandelion_packet_fountain_reorg_pressure_root: String,
    pub reporter_commitment: String,
    pub pre_reorg_reserve_delta_micro_units: i128,
    pub packet_fountain_reorg_lane_claim_reserve_delta_micro_units: i128,
    pub privacy_set_size: u64,
    pub packet_fountain_reorg_risk_score_bps: u64,
    pub submitted_at_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqDandelionPacketFountainReorgInsuranceAttestation {
    pub attestation_id: String,
    pub signal_id: String,
    pub cohort_id: String,
    pub verdict: AttestationVerdict,
    pub attestor_commitment: String,
    pub pq_signature_root: String,
    pub pq_public_key_root: String,
    pub transcript_root: String,
    pub quorum_weight_bps: u64,
    pub pq_security_bits: u16,
    pub observed_packet_fountain_reorg_risk_score_bps: u64,
    pub observed_privacy_set_size: u64,
    pub attested_at_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubmitAttestationRequest {
    pub signal_id: String,
    pub verdict: AttestationVerdict,
    pub attestor_commitment: String,
    pub pq_signature_root: String,
    pub pq_public_key_root: String,
    pub transcript_root: String,
    pub quorum_weight_bps: u64,
    pub pq_security_bits: u16,
    pub observed_packet_fountain_reorg_risk_score_bps: u64,
    pub observed_privacy_set_size: u64,
    pub attested_at_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DandelionPacketFountainReorgDecision {
    pub decision_id: String,
    pub signal_id: String,
    pub cohort_id: String,
    pub policy_id: String,
    pub action: DandelionPacketFountainReorgAction,
    pub decision_root: String,
    pub replacement_claim_reorg_path_root: String,
    pub privacy_filtered_micro_units: u64,
    pub shielded_output_count: u64,
    pub privacy_filter_deadline_slot: u64,
    pub rebate_bps: u64,
    pub decided_at_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettleDecisionRequest {
    pub signal_id: String,
    pub action: DandelionPacketFountainReorgAction,
    pub decision_root: String,
    pub replacement_claim_reorg_path_root: String,
    pub privacy_filtered_micro_units: u64,
    pub shielded_output_count: u64,
    pub rebate_bps: u64,
    pub decided_at_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeDandelionPacketFountainReorgInsuranceRebate {
    pub rebate_id: String,
    pub decision_id: String,
    pub cohort_id: String,
    pub recipient_commitment: String,
    pub asset_id: String,
    pub rebate_micro_units: u64,
    pub fee_saved_micro_units: u64,
    pub rebate_bps: u64,
    pub settlement_slot: u64,
    pub rebate_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishRebateRequest {
    pub decision_id: String,
    pub recipient_commitment: String,
    pub rebate_micro_units: u64,
    pub fee_saved_micro_units: u64,
    pub rebate_bps: u64,
    pub settlement_slot: u64,
    pub rebate_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub scope: DandelionPacketFountainReorgScope,
    pub cohort_id: String,
    pub public_hint_root: String,
    pub max_public_bytes: u64,
    pub consumed_public_bytes: u64,
    pub privacy_set_size: u64,
    pub expires_at_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishRedactionBudgetRequest {
    pub scope: DandelionPacketFountainReorgScope,
    pub cohort_id: String,
    pub public_hint_root: String,
    pub max_public_bytes: u64,
    pub consumed_public_bytes: u64,
    pub privacy_set_size: u64,
    pub expires_at_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub epoch: u64,
    pub slot: u64,
    pub l2_height: u64,
    pub active_policy_count: u64,
    pub active_cohort_count: u64,
    pub active_signal_count: u64,
    pub live_quarantine_count: u64,
    pub total_privacy_filtered_micro_units: u64,
    pub total_rebate_micro_units: u64,
    pub policy_root: String,
    pub cohort_root: String,
    pub signal_root: String,
    pub decision_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub policies: BTreeMap<String, DandelionPacketFountainReorgPolicy>,
    pub cohorts: BTreeMap<String, DandelionPacketFountainReorgInsuranceCohort>,
    pub signals: BTreeMap<String, DandelionPacketFountainReorgSignal>,
    pub attestations: BTreeMap<String, PqDandelionPacketFountainReorgInsuranceAttestation>,
    pub decisions: BTreeMap<String, DandelionPacketFountainReorgDecision>,
    pub rebates: BTreeMap<String, LowFeeDandelionPacketFountainReorgInsuranceRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            policies: BTreeMap::new(),
            cohorts: BTreeMap::new(),
            signals: BTreeMap::new(),
            attestations: BTreeMap::new(),
            decisions: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::default());
        let withdrawal_policy = state
            .register_policy(RegisterPolicyRequest {
                scope: DandelionPacketFountainReorgScope::WithdrawalPacketFountainLane,
                owner_commitment: "owner:dandelion-packet-fountain-reorg-insurance-council-a"
                    .to_string(),
                policy_commitment_root: devnet_root(
                    "policy",
                    "withdrawal-dandelion-packet-fountain-reorg-insurance",
                ),
                claim_source_dandelion_packet_fountain_reorg_set_root: devnet_root(
                    "source-dandelion-tail-packet-fountain-reorg-set",
                    "withdrawal-alpha",
                ),
                claim_target_dandelion_packet_fountain_reorg_set_root: devnet_root(
                    "target-dandelion-tail-packet-fountain-reorg-set",
                    "withdrawal-alpha",
                ),
                claim_rotation_allowlist_root: devnet_root(
                    "reorg_path-allowlist",
                    "withdrawal-alpha",
                ),
                min_privacy_set_size: 524_288,
                min_pre_dandelion_packet_fountain_reorg_reserve_micro_units: 160_000_000,
                min_dandelion_packet_fountain_reorg_lane_claim_reserve_micro_units: 72_000_000,
                max_claim_settlement_fee_bps: 16,
                min_attestation_quorum_bps: 7_200,
                signal_window_slots: 96,
                dandelion_packet_fountain_reorg_window_slots: 720,
                redaction_profile: "withdrawal-dandelion-packet-fountain-reorg-insurance-profile"
                    .to_string(),
            })
            .expect("devnet withdrawal policy");
        let fast_dandelion_exit_policy = state
            .register_policy(RegisterPolicyRequest {
                scope: DandelionPacketFountainReorgScope::FastDandelionPacketFountainReorgRecoveryLane,
                owner_commitment: "owner:fast-dandelion-decoy-insurance-reorg_path-council-b"
                    .to_string(),
                policy_commitment_root: devnet_root(
                    "policy",
                    "fast-dandelion-decoy-insurance-dandelion-packet-fountain-reorg-insurance",
                ),
                claim_source_dandelion_packet_fountain_reorg_set_root: devnet_root(
                    "source-dandelion-tail-packet-fountain-reorg-set",
                    "fast-dandelion-decoy-insurance-beta",
                ),
                claim_target_dandelion_packet_fountain_reorg_set_root: devnet_root(
                    "target-dandelion-tail-packet-fountain-reorg-set",
                    "fast-dandelion-decoy-insurance-beta",
                ),
                claim_rotation_allowlist_root: devnet_root(
                    "reorg_path-allowlist",
                    "fast-dandelion-decoy-insurance-beta",
                ),
                min_privacy_set_size: 393_216,
                min_pre_dandelion_packet_fountain_reorg_reserve_micro_units: 144_000_000,
                min_dandelion_packet_fountain_reorg_lane_claim_reserve_micro_units: 64_000_000,
                max_claim_settlement_fee_bps: 18,
                min_attestation_quorum_bps: 7_000,
                signal_window_slots: 80,
                dandelion_packet_fountain_reorg_window_slots: 640,
                redaction_profile:
                    "fast-dandelion-decoy-insurance-dandelion-packet-fountain-reorg-insurance-profile"
                        .to_string(),
            })
            .expect("devnet fast dandelion_packet_fountain_reorg policy");
        let withdrawal_cohort = state
            .register_cohort(RegisterCohortRequest {
                policy_id: withdrawal_policy,
                bridge_lane_id: "withdrawal-decoy-insurance-alpha".to_string(),
                claim_source_dandelion_packet_fountain_reorg_set_root: devnet_root(
                    "source-dandelion-tail-packet-fountain-reorg-set",
                    "cohort-alpha",
                ),
                claim_target_dandelion_packet_fountain_reorg_set_root: devnet_root(
                    "target-dandelion-tail-packet-fountain-reorg-set",
                    "cohort-alpha",
                ),
                output_set_root: devnet_root("outputs", "cohort-alpha"),
                decoy_insurance_commitment_root: devnet_root("liquidity", "cohort-alpha"),
                pre_dandelion_packet_fountain_reorg_reserve_micro_units: 216_000_000,
                dandelion_packet_fountain_reorg_lane_claim_reserve_micro_units: 96_000_000,
                privacy_set_size: 524_288,
                claim_settlement_fee_bps: 11,
                public_hint_root: devnet_root("hint", "cohort-alpha"),
            })
            .expect("devnet withdrawal cohort");
        let fast_dandelion_exit_cohort = state
            .register_cohort(RegisterCohortRequest {
                policy_id: fast_dandelion_exit_policy,
                bridge_lane_id: "fast-dandelion-decoy-insurance-reorg_path-beta".to_string(),
                claim_source_dandelion_packet_fountain_reorg_set_root: devnet_root(
                    "source-dandelion-tail-packet-fountain-reorg-set",
                    "cohort-beta",
                ),
                claim_target_dandelion_packet_fountain_reorg_set_root: devnet_root(
                    "target-dandelion-tail-packet-fountain-reorg-set",
                    "cohort-beta",
                ),
                output_set_root: devnet_root("outputs", "cohort-beta"),
                decoy_insurance_commitment_root: devnet_root("liquidity", "cohort-beta"),
                pre_dandelion_packet_fountain_reorg_reserve_micro_units: 168_000_000,
                dandelion_packet_fountain_reorg_lane_claim_reserve_micro_units: 76_000_000,
                privacy_set_size: 393_216,
                claim_settlement_fee_bps: 13,
                public_hint_root: devnet_root("hint", "cohort-beta"),
            })
            .expect("devnet fast dandelion_packet_fountain_reorg cohort");
        let signal = state
            .submit_signal(SubmitSignalRequest {
                cohort_id: withdrawal_cohort,
                kind: SignalKind::DandelionPacketFountainReorgLinkagePressure,
                signal_commitment_root: devnet_root("signal", "withdrawal-cluster-pressure"),
                observed_claim_reorg_path_root: devnet_root(
                    "observed-reorg-path",
                    "withdrawal-cluster-pressure",
                ),
                dandelion_packet_fountain_reorg_pressure_root: devnet_root(
                    "pressure",
                    "withdrawal-cluster-pressure",
                ),
                reporter_commitment: "reporter:dandelion-reorg_path-watchtower-11".to_string(),
                pre_reorg_reserve_delta_micro_units: -48_000_000,
                packet_fountain_reorg_lane_claim_reserve_delta_micro_units: 24_000_000,
                privacy_set_size: 524_288,
                packet_fountain_reorg_risk_score_bps: 7_300,
                submitted_at_slot: DEVNET_SLOT,
            })
            .expect("devnet signal");
        state
            .submit_attestation(SubmitAttestationRequest {
                signal_id: signal.clone(),
                verdict: AttestationVerdict::RequireDandelionPacketFountainReorgCoverageGuard,
                attestor_commitment: "attestor:pq-dandelion-packet-fountain-reorg-insurance-a"
                    .to_string(),
                pq_signature_root: devnet_root(
                    "ml-dsa-signature",
                    "withdrawal-dandelion_packet_fountain_reorg-a",
                ),
                pq_public_key_root: devnet_root(
                    "ml-kem-public-key",
                    "withdrawal-dandelion_packet_fountain_reorg-a",
                ),
                transcript_root: devnet_root(
                    "transcript",
                    "withdrawal-dandelion_packet_fountain_reorg-a",
                ),
                quorum_weight_bps: 7_500,
                pq_security_bits: 256,
                observed_packet_fountain_reorg_risk_score_bps: 7_500,
                observed_privacy_set_size: 524_288,
                attested_at_slot: DEVNET_SLOT + 2,
            })
            .expect("devnet attestation a");
        state
            .submit_attestation(SubmitAttestationRequest {
                signal_id: signal.clone(),
                verdict: AttestationVerdict::ConfirmDandelionPacketFountainReorg,
                attestor_commitment: "attestor:pq-dandelion-packet-fountain-reorg-insurance-b"
                    .to_string(),
                pq_signature_root: devnet_root(
                    "slh-dsa-signature",
                    "withdrawal-dandelion_packet_fountain_reorg-b",
                ),
                pq_public_key_root: devnet_root(
                    "ml-kem-public-key",
                    "withdrawal-dandelion_packet_fountain_reorg-b",
                ),
                transcript_root: devnet_root(
                    "transcript",
                    "withdrawal-dandelion_packet_fountain_reorg-b",
                ),
                quorum_weight_bps: 8_700,
                pq_security_bits: 256,
                observed_packet_fountain_reorg_risk_score_bps: 7_800,
                observed_privacy_set_size: 524_288,
                attested_at_slot: DEVNET_SLOT + 3,
            })
            .expect("devnet attestation b");
        let decision = state
            .settle_decision(SettleDecisionRequest {
                signal_id: signal,
                action: DandelionPacketFountainReorgAction::SettleDandelionPacketFountainReorg,
                decision_root: devnet_root(
                    "decision",
                    "withdrawal-liquidity-dandelion_packet_fountain_reorg",
                ),
                replacement_claim_reorg_path_root: devnet_root(
                    "replacement-reorg_path",
                    "withdrawal-dandelion_packet_fountain_reorg",
                ),
                privacy_filtered_micro_units: 32_000_000,
                shielded_output_count: 4_096,
                rebate_bps: 8,
                decided_at_slot: DEVNET_SLOT + 5,
            })
            .expect("devnet dandelion_packet_fountain_reorg decision");
        state
            .publish_rebate(PublishRebateRequest {
                decision_id: decision,
                recipient_commitment:
                    "recipient:dandelion-packet-fountain-reorg-insurance-fee-sponsor".to_string(),
                rebate_micro_units: 22_000,
                fee_saved_micro_units: 88_000,
                rebate_bps: 8,
                settlement_slot: DEVNET_SLOT + 6,
                rebate_root: devnet_root("rebate", "withdrawal-dandelion_packet_fountain_reorg"),
            })
            .expect("devnet rebate");
        state
            .publish_redaction_budget(PublishRedactionBudgetRequest {
                scope:
                    DandelionPacketFountainReorgScope::FastDandelionPacketFountainReorgRecoveryLane,
                cohort_id: fast_dandelion_exit_cohort,
                public_hint_root: devnet_root(
                    "redaction-hint",
                    "fast-dandelion-decoy-insurance-beta",
                ),
                max_public_bytes: 1_536,
                consumed_public_bytes: 512,
                privacy_set_size: 393_216,
                expires_at_slot: DEVNET_SLOT + 720,
            })
            .expect("devnet redaction budget");
        state
            .publish_operator_summary(DEVNET_EPOCH, DEVNET_SLOT + 8, DEVNET_L2_HEIGHT)
            .expect("devnet operator summary");
        state
    }

    pub fn register_policy(&mut self, request: RegisterPolicyRequest) -> Result<String> {
        ensure_capacity(
            self.policies.len(),
            MAX_POLICIES,
            "Dandelion packet-fountain reorg-phase privacy guard policies",
        )?;
        ensure_non_empty(&request.owner_commitment, "owner_commitment")?;
        ensure_non_empty(&request.policy_commitment_root, "policy_commitment_root")?;
        ensure_non_empty(
            &request.claim_source_dandelion_packet_fountain_reorg_set_root,
            "claim_source_dandelion_packet_fountain_reorg_set_root",
        )?;
        ensure_non_empty(
            &request.claim_target_dandelion_packet_fountain_reorg_set_root,
            "claim_target_dandelion_packet_fountain_reorg_set_root",
        )?;
        ensure_non_empty(
            &request.claim_rotation_allowlist_root,
            "claim_rotation_allowlist_root",
        )?;
        ensure_non_empty(&request.redaction_profile, "redaction_profile")?;
        ensure_bps(
            request.max_claim_settlement_fee_bps,
            "max_claim_settlement_fee_bps",
        )?;
        ensure_bps(
            request.min_attestation_quorum_bps,
            "min_attestation_quorum_bps",
        )?;
        if request.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("policy privacy set below runtime floor".to_string());
        }
        if request.min_pre_dandelion_packet_fountain_reorg_reserve_micro_units
            < self
                .config
                .min_pre_dandelion_packet_fountain_reorg_reserve_micro_units
        {
            return Err("policy source liquidity below runtime floor".to_string());
        }
        if request.min_dandelion_packet_fountain_reorg_lane_claim_reserve_micro_units
            < self
                .config
                .min_dandelion_packet_fountain_reorg_lane_claim_reserve_micro_units
        {
            return Err("policy target liquidity below runtime floor".to_string());
        }
        let policy_id = stable_id(
            "dandelion-packet-fountain-reorg-insurance-policy",
            &[
                HashPart::Str(request.scope.as_str()),
                HashPart::Str(&request.owner_commitment),
                HashPart::Str(&request.policy_commitment_root),
                HashPart::Str(&request.claim_source_dandelion_packet_fountain_reorg_set_root),
            ],
        );
        if self.policies.contains_key(&policy_id) {
            return Err(format!(
                "Dandelion packet-fountain reorg-phase privacy guard policy {policy_id} already exists"
            ));
        }
        self.policies.insert(
            policy_id.clone(),
            DandelionPacketFountainReorgPolicy {
                policy_id: policy_id.clone(),
                scope: request.scope,
                owner_commitment: request.owner_commitment,
                policy_commitment_root: request.policy_commitment_root,
                claim_source_dandelion_packet_fountain_reorg_set_root: request
                    .claim_source_dandelion_packet_fountain_reorg_set_root,
                claim_target_dandelion_packet_fountain_reorg_set_root: request
                    .claim_target_dandelion_packet_fountain_reorg_set_root,
                claim_rotation_allowlist_root: request.claim_rotation_allowlist_root,
                min_privacy_set_size: request.min_privacy_set_size,
                min_pre_dandelion_packet_fountain_reorg_reserve_micro_units: request
                    .min_pre_dandelion_packet_fountain_reorg_reserve_micro_units,
                min_dandelion_packet_fountain_reorg_lane_claim_reserve_micro_units: request
                    .min_dandelion_packet_fountain_reorg_lane_claim_reserve_micro_units,
                max_claim_settlement_fee_bps: request.max_claim_settlement_fee_bps,
                min_attestation_quorum_bps: request.min_attestation_quorum_bps,
                signal_window_slots: request.signal_window_slots,
                dandelion_packet_fountain_reorg_window_slots: request
                    .dandelion_packet_fountain_reorg_window_slots,
                active: true,
                redaction_profile: request.redaction_profile,
            },
        );
        self.counters.policies_registered = self.counters.policies_registered.saturating_add(1);
        self.refresh_roots();
        Ok(policy_id)
    }

    pub fn register_cohort(&mut self, request: RegisterCohortRequest) -> Result<String> {
        ensure_capacity(
            self.cohorts.len(),
            MAX_COHORTS,
            "Dandelion reorg_path privacy cohorts",
        )?;
        let policy = self.policies.get(&request.policy_id).ok_or_else(|| {
            format!(
                "unknown Dandelion packet-fountain reorg-phase privacy guard policy {}",
                request.policy_id
            )
        })?;
        ensure_non_empty(&request.bridge_lane_id, "bridge_lane_id")?;
        ensure_non_empty(
            &request.claim_source_dandelion_packet_fountain_reorg_set_root,
            "claim_source_dandelion_packet_fountain_reorg_set_root",
        )?;
        ensure_non_empty(
            &request.claim_target_dandelion_packet_fountain_reorg_set_root,
            "claim_target_dandelion_packet_fountain_reorg_set_root",
        )?;
        ensure_non_empty(&request.output_set_root, "output_set_root")?;
        ensure_non_empty(
            &request.decoy_insurance_commitment_root,
            "decoy_insurance_commitment_root",
        )?;
        ensure_non_empty(&request.public_hint_root, "public_hint_root")?;
        ensure_bps(request.claim_settlement_fee_bps, "claim_settlement_fee_bps")?;
        if request.claim_settlement_fee_bps > policy.max_claim_settlement_fee_bps {
            return Err("cohort reorg_path fee exceeds policy cap".to_string());
        }
        if request.pre_dandelion_packet_fountain_reorg_reserve_micro_units
            < policy.min_pre_dandelion_packet_fountain_reorg_reserve_micro_units
        {
            return Err("cohort source liquidity below policy floor".to_string());
        }
        if request.dandelion_packet_fountain_reorg_lane_claim_reserve_micro_units
            < policy.min_dandelion_packet_fountain_reorg_lane_claim_reserve_micro_units
        {
            return Err("cohort target liquidity below policy floor".to_string());
        }
        if request.privacy_set_size < policy.min_privacy_set_size {
            return Err("cohort privacy set below policy floor".to_string());
        }
        let cohort_id = stable_id(
            "dandelion-packet-fountain-reorg-insurance-cohort",
            &[
                HashPart::Str(&request.policy_id),
                HashPart::Str(&request.bridge_lane_id),
                HashPart::Str(&request.claim_source_dandelion_packet_fountain_reorg_set_root),
                HashPart::Str(&request.decoy_insurance_commitment_root),
            ],
        );
        if self.cohorts.contains_key(&cohort_id) {
            return Err(format!(
                "Dandelion packet-fountain reorg-phase privacy guard cohort {cohort_id} already exists"
            ));
        }
        self.cohorts.insert(
            cohort_id.clone(),
            DandelionPacketFountainReorgInsuranceCohort {
                cohort_id: cohort_id.clone(),
                policy_id: request.policy_id,
                scope: policy.scope,
                status: CohortStatus::Active,
                bridge_lane_id: request.bridge_lane_id,
                claim_source_dandelion_packet_fountain_reorg_set_root: request
                    .claim_source_dandelion_packet_fountain_reorg_set_root,
                claim_target_dandelion_packet_fountain_reorg_set_root: request
                    .claim_target_dandelion_packet_fountain_reorg_set_root,
                output_set_root: request.output_set_root,
                decoy_insurance_commitment_root: request.decoy_insurance_commitment_root,
                pre_dandelion_packet_fountain_reorg_reserve_micro_units: request
                    .pre_dandelion_packet_fountain_reorg_reserve_micro_units,
                dandelion_packet_fountain_reorg_lane_claim_reserve_micro_units: request
                    .dandelion_packet_fountain_reorg_lane_claim_reserve_micro_units,
                privacy_set_size: request.privacy_set_size,
                claim_settlement_fee_bps: request.claim_settlement_fee_bps,
                active_signal_count: 0,
                privacy_filter_deadline_slot: 0,
                public_hint_root: request.public_hint_root,
            },
        );
        self.counters.cohorts_registered = self.counters.cohorts_registered.saturating_add(1);
        self.refresh_live_counts();
        self.refresh_roots();
        Ok(cohort_id)
    }

    pub fn submit_signal(&mut self, request: SubmitSignalRequest) -> Result<String> {
        ensure_capacity(
            self.signals.len(),
            MAX_SIGNALS,
            "Dandelion packet-fountain reorg-phase privacy guard signals",
        )?;
        let cohort = self
            .cohorts
            .get(&request.cohort_id)
            .ok_or_else(|| {
                format!(
                    "unknown Dandelion packet-fountain reorg-phase privacy guard cohort {}",
                    request.cohort_id
                )
            })?
            .clone();
        let policy = self.policies.get(&cohort.policy_id).ok_or_else(|| {
            format!(
                "unknown Dandelion packet-fountain reorg-phase privacy guard policy {}",
                cohort.policy_id
            )
        })?;
        ensure_non_empty(&request.signal_commitment_root, "signal_commitment_root")?;
        ensure_non_empty(
            &request.observed_claim_reorg_path_root,
            "observed_claim_reorg_path_root",
        )?;
        ensure_non_empty(
            &request.dandelion_packet_fountain_reorg_pressure_root,
            "dandelion_packet_fountain_reorg_pressure_root",
        )?;
        ensure_non_empty(&request.reporter_commitment, "reporter_commitment")?;
        ensure_bps(
            request.packet_fountain_reorg_risk_score_bps,
            "packet_fountain_reorg_risk_score_bps",
        )?;
        if request.privacy_set_size < policy.min_privacy_set_size {
            return Err("signal privacy set below policy floor".to_string());
        }
        let signal_id = stable_id(
            "dandelion-packet-fountain-reorg-insurance-signal",
            &[
                HashPart::Str(&request.cohort_id),
                HashPart::Str(&request.signal_commitment_root),
                HashPart::U64(request.submitted_at_slot),
            ],
        );
        if self.signals.contains_key(&signal_id) {
            return Err(format!(
                "Dandelion packet-fountain reorg-phase privacy guard signal {signal_id} already exists"
            ));
        }
        let expires_at_slot = request
            .submitted_at_slot
            .saturating_add(policy.signal_window_slots);
        self.signals.insert(
            signal_id.clone(),
            DandelionPacketFountainReorgSignal {
                signal_id: signal_id.clone(),
                cohort_id: request.cohort_id.clone(),
                policy_id: cohort.policy_id,
                kind: request.kind,
                status: SignalStatus::Submitted,
                signal_commitment_root: request.signal_commitment_root,
                observed_claim_reorg_path_root: request.observed_claim_reorg_path_root,
                dandelion_packet_fountain_reorg_pressure_root: request
                    .dandelion_packet_fountain_reorg_pressure_root,
                reporter_commitment: request.reporter_commitment,
                pre_reorg_reserve_delta_micro_units: request.pre_reorg_reserve_delta_micro_units,
                packet_fountain_reorg_lane_claim_reserve_delta_micro_units: request
                    .packet_fountain_reorg_lane_claim_reserve_delta_micro_units,
                privacy_set_size: request.privacy_set_size,
                packet_fountain_reorg_risk_score_bps: request.packet_fountain_reorg_risk_score_bps,
                submitted_at_slot: request.submitted_at_slot,
                expires_at_slot,
                attestation_ids: BTreeSet::new(),
            },
        );
        if let Some(cohort) = self.cohorts.get_mut(&request.cohort_id) {
            cohort.active_signal_count = cohort.active_signal_count.saturating_add(1);
        }
        self.counters.signals_submitted = self.counters.signals_submitted.saturating_add(1);
        self.refresh_live_counts();
        self.refresh_roots();
        Ok(signal_id)
    }

    pub fn submit_attestation(&mut self, request: SubmitAttestationRequest) -> Result<String> {
        ensure_capacity(
            self.attestations.len(),
            MAX_ATTESTATIONS,
            "Dandelion packet-fountain reorg-phase privacy guard attestations",
        )?;
        let signal = self
            .signals
            .get(&request.signal_id)
            .ok_or_else(|| {
                format!(
                    "unknown Dandelion packet-fountain reorg-phase privacy guard signal {}",
                    request.signal_id
                )
            })?
            .clone();
        let policy = self.policies.get(&signal.policy_id).ok_or_else(|| {
            format!(
                "unknown Dandelion packet-fountain reorg-phase privacy guard policy {}",
                signal.policy_id
            )
        })?;
        ensure_non_empty(&request.attestor_commitment, "attestor_commitment")?;
        ensure_non_empty(&request.pq_signature_root, "pq_signature_root")?;
        ensure_non_empty(&request.pq_public_key_root, "pq_public_key_root")?;
        ensure_non_empty(&request.transcript_root, "transcript_root")?;
        ensure_bps(request.quorum_weight_bps, "quorum_weight_bps")?;
        ensure_bps(
            request.observed_packet_fountain_reorg_risk_score_bps,
            "observed_packet_fountain_reorg_risk_score_bps",
        )?;
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("PQ attestation security below runtime floor".to_string());
        }
        if request.quorum_weight_bps < policy.min_attestation_quorum_bps {
            return Err("attestation quorum below policy threshold".to_string());
        }
        if request.observed_privacy_set_size < policy.min_privacy_set_size {
            return Err("attested privacy set below policy floor".to_string());
        }
        let attestation_id = stable_id(
            "dandelion-packet-fountain-reorg-insurance-pq-attestation",
            &[
                HashPart::Str(&request.signal_id),
                HashPart::Str(&request.attestor_commitment),
                HashPart::Str(&request.pq_signature_root),
                HashPart::U64(request.attested_at_slot),
            ],
        );
        if self.attestations.contains_key(&attestation_id) {
            return Err(format!(
                "Dandelion packet-fountain reorg-phase privacy guard attestation {attestation_id} already exists"
            ));
        }
        self.attestations.insert(
            attestation_id.clone(),
            PqDandelionPacketFountainReorgInsuranceAttestation {
                attestation_id: attestation_id.clone(),
                signal_id: request.signal_id.clone(),
                cohort_id: signal.cohort_id.clone(),
                verdict: request.verdict,
                attestor_commitment: request.attestor_commitment,
                pq_signature_root: request.pq_signature_root,
                pq_public_key_root: request.pq_public_key_root,
                transcript_root: request.transcript_root,
                quorum_weight_bps: request.quorum_weight_bps,
                pq_security_bits: request.pq_security_bits,
                observed_packet_fountain_reorg_risk_score_bps: request
                    .observed_packet_fountain_reorg_risk_score_bps,
                observed_privacy_set_size: request.observed_privacy_set_size,
                attested_at_slot: request.attested_at_slot,
            },
        );
        if let Some(signal) = self.signals.get_mut(&request.signal_id) {
            signal.attestation_ids.insert(attestation_id.clone());
            signal.status = SignalStatus::Attested;
        }
        self.counters.attestations_recorded = self.counters.attestations_recorded.saturating_add(1);
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn settle_decision(&mut self, request: SettleDecisionRequest) -> Result<String> {
        ensure_capacity(
            self.decisions.len(),
            MAX_DECISIONS,
            "Dandelion packet-fountain reorg-phase privacy guard decisions",
        )?;
        let signal = self
            .signals
            .get(&request.signal_id)
            .ok_or_else(|| {
                format!(
                    "unknown Dandelion packet-fountain reorg-phase privacy guard signal {}",
                    request.signal_id
                )
            })?
            .clone();
        let policy = self.policies.get(&signal.policy_id).ok_or_else(|| {
            format!(
                "unknown Dandelion packet-fountain reorg-phase privacy guard policy {}",
                signal.policy_id
            )
        })?;
        ensure_non_empty(&request.decision_root, "decision_root")?;
        ensure_non_empty(
            &request.replacement_claim_reorg_path_root,
            "replacement_claim_reorg_path_root",
        )?;
        ensure_bps(request.rebate_bps, "rebate_bps")?;
        let privacy_filter_deadline_slot = match request.action {
            DandelionPacketFountainReorgAction::QueueDandelionPacketFountainReorgInsuranceClaimReview
            | DandelionPacketFountainReorgAction::SettleDandelionPacketFountainReorg
            | DandelionPacketFountainReorgAction::RotateDandelionPacketFountainReorgInsuranceSettlementCohort => {
                request
                    .decided_at_slot
                    .saturating_add(policy.dandelion_packet_fountain_reorg_window_slots)
            }
            DandelionPacketFountainReorgAction::QuarantinePacketFountainReorgPath
            | DandelionPacketFountainReorgAction::EmergencyPause => request
                .decided_at_slot
                .saturating_add(policy.dandelion_packet_fountain_reorg_window_slots / 2),
            _ => 0,
        };
        let decision_id = stable_id(
            "dandelion-packet-fountain-reorg-insurance-decision",
            &[
                HashPart::Str(&request.signal_id),
                HashPart::Str(&request.decision_root),
                HashPart::U64(request.decided_at_slot),
            ],
        );
        if self.decisions.contains_key(&decision_id) {
            return Err(format!(
                "Dandelion packet-fountain reorg-phase privacy guard decision {decision_id} already exists"
            ));
        }
        self.decisions.insert(
            decision_id.clone(),
            DandelionPacketFountainReorgDecision {
                decision_id: decision_id.clone(),
                signal_id: request.signal_id.clone(),
                cohort_id: signal.cohort_id.clone(),
                policy_id: signal.policy_id.clone(),
                action: request.action,
                decision_root: request.decision_root,
                replacement_claim_reorg_path_root: request.replacement_claim_reorg_path_root,
                privacy_filtered_micro_units: request.privacy_filtered_micro_units,
                shielded_output_count: request.shielded_output_count,
                privacy_filter_deadline_slot,
                rebate_bps: request.rebate_bps,
                decided_at_slot: request.decided_at_slot,
            },
        );
        if let Some(signal) = self.signals.get_mut(&request.signal_id) {
            signal.status = match request.action {
                DandelionPacketFountainReorgAction::QueueDandelionPacketFountainReorgInsuranceClaimReview => {
                    SignalStatus::PacketFountainReorgPathQueued
                }
                DandelionPacketFountainReorgAction::SettleDandelionPacketFountainReorg
                | DandelionPacketFountainReorgAction::RotateDandelionPacketFountainReorgInsuranceSettlementCohort => {
                    SignalStatus::DandelionPacketFountainReorgInsuring
                }
                DandelionPacketFountainReorgAction::QuarantinePacketFountainReorgPath
                | DandelionPacketFountainReorgAction::EmergencyPause => SignalStatus::Quarantined,
                DandelionPacketFountainReorgAction::Release => SignalStatus::Settled,
                DandelionPacketFountainReorgAction::Reject => SignalStatus::Rejected,
                DandelionPacketFountainReorgAction::Expire => SignalStatus::Expired,
                DandelionPacketFountainReorgAction::Observe => SignalStatus::Attested,
            };
        }
        if let Some(cohort) = self.cohorts.get_mut(&signal.cohort_id) {
            match request.action {
                DandelionPacketFountainReorgAction::QueueDandelionPacketFountainReorgInsuranceClaimReview => {
                    cohort.status = CohortStatus::PacketFountainReorgPathPending;
                    cohort.privacy_filter_deadline_slot = privacy_filter_deadline_slot;
                }
                DandelionPacketFountainReorgAction::SettleDandelionPacketFountainReorg => {
                    cohort.status = CohortStatus::DandelionPacketFountainReorgInsuring;
                    cohort.pre_dandelion_packet_fountain_reorg_reserve_micro_units = cohort
                        .pre_dandelion_packet_fountain_reorg_reserve_micro_units
                        .saturating_sub(request.privacy_filtered_micro_units);
                    cohort.dandelion_packet_fountain_reorg_lane_claim_reserve_micro_units = cohort
                        .dandelion_packet_fountain_reorg_lane_claim_reserve_micro_units
                        .saturating_add(request.privacy_filtered_micro_units);
                    cohort.privacy_filter_deadline_slot = privacy_filter_deadline_slot;
                    self.counters.dandelion_packet_fountain_reorg_filters_settled = self
                        .counters
                        .dandelion_packet_fountain_reorg_filters_settled
                        .saturating_add(1);
                    self.counters.total_privacy_filtered_micro_units = self
                        .counters
                        .total_privacy_filtered_micro_units
                        .saturating_add(request.privacy_filtered_micro_units);
                }
                DandelionPacketFountainReorgAction::RotateDandelionPacketFountainReorgInsuranceSettlementCohort => {
                    cohort.status = CohortStatus::Rotating;
                    cohort.privacy_filter_deadline_slot = privacy_filter_deadline_slot;
                    self.counters.cohorts_rotated = self.counters.cohorts_rotated.saturating_add(1);
                }
                DandelionPacketFountainReorgAction::QuarantinePacketFountainReorgPath => {
                    cohort.status = CohortStatus::Quarantined;
                    cohort.privacy_filter_deadline_slot = privacy_filter_deadline_slot;
                    self.counters.claim_reorg_paths_quarantined = self
                        .counters
                        .claim_reorg_paths_quarantined
                        .saturating_add(1);
                }
                DandelionPacketFountainReorgAction::EmergencyPause => {
                    cohort.status = CohortStatus::Paused;
                    cohort.privacy_filter_deadline_slot = privacy_filter_deadline_slot;
                    self.counters.claim_reorg_paths_quarantined = self
                        .counters
                        .claim_reorg_paths_quarantined
                        .saturating_add(1);
                }
                DandelionPacketFountainReorgAction::Release => {
                    cohort.status = CohortStatus::Settled;
                    cohort.privacy_filter_deadline_slot = 0;
                    self.counters.cohorts_released =
                        self.counters.cohorts_released.saturating_add(1);
                }
                _ => {}
            }
        }
        self.counters.decisions_published = self.counters.decisions_published.saturating_add(1);
        self.refresh_live_counts();
        self.refresh_roots();
        Ok(decision_id)
    }

    pub fn publish_rebate(&mut self, request: PublishRebateRequest) -> Result<String> {
        ensure_capacity(
            self.rebates.len(),
            MAX_REBATES,
            "Dandelion packet-fountain reorg-phase privacy guard rebates",
        )?;
        let decision = self.decisions.get(&request.decision_id).ok_or_else(|| {
            format!(
                "unknown Dandelion packet-fountain reorg-phase privacy guard decision {}",
                request.decision_id
            )
        })?;
        ensure_non_empty(&request.recipient_commitment, "recipient_commitment")?;
        ensure_non_empty(&request.rebate_root, "rebate_root")?;
        ensure_bps(request.rebate_bps, "rebate_bps")?;
        let rebate_id = stable_id(
            "dandelion-packet-fountain-reorg-insurance-low-fee-rebate",
            &[
                HashPart::Str(&request.decision_id),
                HashPart::Str(&request.recipient_commitment),
                HashPart::U64(request.settlement_slot),
            ],
        );
        if self.rebates.contains_key(&rebate_id) {
            return Err(format!(
                "Dandelion packet-fountain reorg-phase privacy guard rebate {rebate_id} already exists"
            ));
        }
        self.rebates.insert(
            rebate_id.clone(),
            LowFeeDandelionPacketFountainReorgInsuranceRebate {
                rebate_id: rebate_id.clone(),
                decision_id: request.decision_id,
                cohort_id: decision.cohort_id.clone(),
                recipient_commitment: request.recipient_commitment,
                asset_id: self.config.fee_asset_id.clone(),
                rebate_micro_units: request.rebate_micro_units,
                fee_saved_micro_units: request.fee_saved_micro_units,
                rebate_bps: request.rebate_bps,
                settlement_slot: request.settlement_slot,
                rebate_root: request.rebate_root,
            },
        );
        self.counters.rebates_published = self.counters.rebates_published.saturating_add(1);
        self.counters.total_rebate_micro_units = self
            .counters
            .total_rebate_micro_units
            .saturating_add(request.rebate_micro_units);
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn publish_redaction_budget(
        &mut self,
        request: PublishRedactionBudgetRequest,
    ) -> Result<String> {
        ensure_capacity(
            self.redaction_budgets.len(),
            MAX_REDACTION_BUDGETS,
            "Dandelion packet-fountain reorg-phase privacy guard redaction budgets",
        )?;
        ensure_non_empty(&request.cohort_id, "cohort_id")?;
        ensure_non_empty(&request.public_hint_root, "public_hint_root")?;
        if !self.cohorts.contains_key(&request.cohort_id) {
            return Err(format!(
                "unknown Dandelion packet-fountain reorg-phase privacy guard cohort {}",
                request.cohort_id
            ));
        }
        if request.consumed_public_bytes > request.max_public_bytes {
            return Err("redaction consumed bytes exceed max".to_string());
        }
        if request.max_public_bytes > self.config.max_public_redaction_bytes {
            return Err("redaction budget exceeds runtime public byte cap".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("redaction privacy set below runtime floor".to_string());
        }
        let budget_id = stable_id(
            "dandelion-packet-fountain-reorg-insurance-redaction-budget",
            &[
                HashPart::Str(request.scope.as_str()),
                HashPart::Str(&request.cohort_id),
                HashPart::Str(&request.public_hint_root),
                HashPart::U64(request.expires_at_slot),
            ],
        );
        if self.redaction_budgets.contains_key(&budget_id) {
            return Err(format!(
                "Dandelion packet-fountain reorg-phase privacy guard redaction budget {budget_id} already exists"
            ));
        }
        self.redaction_budgets.insert(
            budget_id.clone(),
            RedactionBudget {
                budget_id: budget_id.clone(),
                scope: request.scope,
                cohort_id: request.cohort_id,
                public_hint_root: request.public_hint_root,
                max_public_bytes: request.max_public_bytes,
                consumed_public_bytes: request.consumed_public_bytes,
                privacy_set_size: request.privacy_set_size,
                expires_at_slot: request.expires_at_slot,
            },
        );
        self.counters.redaction_budgets_published =
            self.counters.redaction_budgets_published.saturating_add(1);
        self.refresh_roots();
        Ok(budget_id)
    }

    pub fn publish_operator_summary(
        &mut self,
        epoch: u64,
        slot: u64,
        l2_height: u64,
    ) -> Result<String> {
        ensure_capacity(
            self.operator_summaries.len(),
            MAX_OPERATOR_SUMMARIES,
            "Dandelion packet-fountain reorg-phase privacy guard operator summaries",
        )?;
        self.refresh_live_counts();
        let active_policy_count = self
            .policies
            .values()
            .filter(|policy| policy.active)
            .count() as u64;
        let active_cohort_count = self
            .cohorts
            .values()
            .filter(|cohort| !matches!(cohort.status, CohortStatus::Retired))
            .count() as u64;
        let summary_id = stable_id(
            "dandelion-packet-fountain-reorg-insurance-operator-summary",
            &[
                HashPart::U64(epoch),
                HashPart::U64(slot),
                HashPart::Str(&self.roots.state_root),
            ],
        );
        self.operator_summaries.insert(
            summary_id.clone(),
            OperatorSummary {
                summary_id: summary_id.clone(),
                epoch,
                slot,
                l2_height,
                active_policy_count,
                active_cohort_count,
                active_signal_count: self.counters.active_signal_count,
                live_quarantine_count: self.counters.live_quarantine_count,
                total_privacy_filtered_micro_units: self
                    .counters
                    .total_privacy_filtered_micro_units,
                total_rebate_micro_units: self.counters.total_rebate_micro_units,
                policy_root: self.roots.policy_root.clone(),
                cohort_root: self.roots.cohort_root.clone(),
                signal_root: self.roots.signal_root.clone(),
                decision_root: self.roots.decision_root.clone(),
                state_root: self.roots.state_root.clone(),
            },
        );
        self.counters.operator_summaries_published =
            self.counters.operator_summaries_published.saturating_add(1);
        self.refresh_roots();
        Ok(summary_id)
    }

    fn refresh_live_counts(&mut self) {
        self.counters.active_signal_count = self
            .signals
            .values()
            .filter(|signal| {
                matches!(
                    signal.status,
                    SignalStatus::Submitted
                        | SignalStatus::Attested
                        | SignalStatus::PacketFountainReorgPathQueued
                        | SignalStatus::DandelionPacketFountainReorgInsuring
                        | SignalStatus::Quarantined
                )
            })
            .count() as u64;
        self.counters.live_quarantine_count = self
            .cohorts
            .values()
            .filter(|cohort| {
                matches!(
                    cohort.status,
                    CohortStatus::Quarantined | CohortStatus::Paused
                )
            })
            .count() as u64;
    }

    fn refresh_roots(&mut self) {
        self.roots.config_root = object_root("config", &self.config);
        self.roots.policy_root = map_root("policies", &self.policies);
        self.roots.cohort_root = map_root("cohorts", &self.cohorts);
        self.roots.signal_root = map_root("signals", &self.signals);
        self.roots.attestation_root = map_root("attestations", &self.attestations);
        self.roots.decision_root = map_root("decisions", &self.decisions);
        self.roots.rebate_root = map_root("rebates", &self.rebates);
        self.roots.redaction_root = map_root("redactions", &self.redaction_budgets);
        self.roots.operator_summary_root = map_root("operator-summaries", &self.operator_summaries);
        self.roots.counters_root = object_root("counters", &self.counters);
        self.roots.state_root = merkle_root(
            "bridge-dandelion-packet-fountain-reorg-insurance:state",
            &[
                json!({ "config_root": self.roots.config_root }),
                json!({ "policy_root": self.roots.policy_root }),
                json!({ "cohort_root": self.roots.cohort_root }),
                json!({ "signal_root": self.roots.signal_root }),
                json!({ "attestation_root": self.roots.attestation_root }),
                json!({ "decision_root": self.roots.decision_root }),
                json!({ "rebate_root": self.roots.rebate_root }),
                json!({ "redaction_root": self.roots.redaction_root }),
                json!({ "operator_summary_root": self.roots.operator_summary_root }),
                json!({ "counters_root": self.roots.counters_root }),
            ],
        );
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": self.config.hash_suite,
            "pq_claim_settlement_insurance_suite": self.config.pq_claim_settlement_insurance_suite,
            "dandelion_packet_fountain_reorg_insurance_suite": self.config.dandelion_packet_fountain_reorg_insurance_suite,
            "rebate_suite": self.config.rebate_suite,
            "redaction_suite": self.config.redaction_suite,
            "fee_asset_id": self.config.fee_asset_id,
            "bridge_asset_id": self.config.bridge_asset_id,
            "min_privacy_set_size": self.config.min_privacy_set_size,
            "target_privacy_set_size": self.config.target_privacy_set_size,
            "min_pq_security_bits": self.config.min_pq_security_bits,
            "dandelion_packet_fountain_reorg_window_slots": self.config.dandelion_packet_fountain_reorg_window_slots,
            "signal_window_slots": self.config.signal_window_slots,
            "max_claim_settlement_fee_bps": self.config.max_claim_settlement_fee_bps,
            "target_rebate_bps": self.config.target_rebate_bps,
            "counters": self.counters,
            "roots": self.roots,
            "policy_count": self.policies.len(),
            "cohort_count": self.cohorts.len(),
            "signal_count": self.signals.len(),
            "attestation_count": self.attestations.len(),
            "decision_count": self.decisions.len(),
            "rebate_count": self.rebates.len(),
            "redaction_budget_count": self.redaction_budgets.len(),
            "operator_summary_count": self.operator_summaries.len(),
            "policies": self.policies.values().map(|policy| json!({
                "policy_id": policy.policy_id,
                "scope": policy.scope,
                "min_privacy_set_size": policy.min_privacy_set_size,
                "min_pre_dandelion_packet_fountain_reorg_reserve_micro_units": policy.min_pre_dandelion_packet_fountain_reorg_reserve_micro_units,
                "min_dandelion_packet_fountain_reorg_lane_claim_reserve_micro_units": policy.min_dandelion_packet_fountain_reorg_lane_claim_reserve_micro_units,
                "max_claim_settlement_fee_bps": policy.max_claim_settlement_fee_bps,
                "min_attestation_quorum_bps": policy.min_attestation_quorum_bps,
                "active": policy.active,
            })).collect::<Vec<_>>(),
            "cohorts": self.cohorts.values().map(|cohort| json!({
                "cohort_id": cohort.cohort_id,
                "policy_id": cohort.policy_id,
                "scope": cohort.scope,
                "status": cohort.status,
                "bridge_lane_id": cohort.bridge_lane_id,
                "pre_dandelion_packet_fountain_reorg_reserve_micro_units": cohort.pre_dandelion_packet_fountain_reorg_reserve_micro_units,
                "dandelion_packet_fountain_reorg_lane_claim_reserve_micro_units": cohort.dandelion_packet_fountain_reorg_lane_claim_reserve_micro_units,
                "privacy_set_size": cohort.privacy_set_size,
                "claim_settlement_fee_bps": cohort.claim_settlement_fee_bps,
                "active_signal_count": cohort.active_signal_count,
                "privacy_filter_deadline_slot": cohort.privacy_filter_deadline_slot,
                "public_hint_root": cohort.public_hint_root,
            })).collect::<Vec<_>>(),
            "signals": self.signals.values().map(|signal| json!({
                "signal_id": signal.signal_id,
                "cohort_id": signal.cohort_id,
                "kind": signal.kind,
                "status": signal.status,
                "privacy_set_size": signal.privacy_set_size,
                "packet_fountain_reorg_risk_score_bps": signal.packet_fountain_reorg_risk_score_bps,
                "submitted_at_slot": signal.submitted_at_slot,
                "expires_at_slot": signal.expires_at_slot,
                "attestation_count": signal.attestation_ids.len(),
            })).collect::<Vec<_>>(),
            "decisions": self.decisions.values().map(|decision| json!({
                "decision_id": decision.decision_id,
                "signal_id": decision.signal_id,
                "cohort_id": decision.cohort_id,
                "action": decision.action,
                "privacy_filtered_micro_units": decision.privacy_filtered_micro_units,
                "shielded_output_count": decision.shielded_output_count,
                "privacy_filter_deadline_slot": decision.privacy_filter_deadline_slot,
                "rebate_bps": decision.rebate_bps,
                "decided_at_slot": decision.decided_at_slot,
            })).collect::<Vec<_>>(),
            "operator_summaries": self.operator_summaries.values().collect::<Vec<_>>(),
        })
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = State::devnet();
    let cohort_id = state.cohorts.keys().next().cloned().unwrap_or_default();
    let signal = state
        .submit_signal(SubmitSignalRequest {
            cohort_id,
            kind: SignalKind::DandelionPacketFountainReorgGraphLinkagePressure,
            signal_commitment_root: devnet_root("signal", "demo-packet-fountain-reorg-pressure"),
            observed_claim_reorg_path_root: devnet_root(
                "observed-reorg-path",
                "demo-packet-fountain-reorg-pressure",
            ),
            dandelion_packet_fountain_reorg_pressure_root: devnet_root(
                "pressure",
                "demo-packet-fountain-reorg-pressure",
            ),
            reporter_commitment: "reporter:demo-packet-fountain-watchtower".to_string(),
            pre_reorg_reserve_delta_micro_units: -10_000_000,
            packet_fountain_reorg_lane_claim_reserve_delta_micro_units: 8_000_000,
            privacy_set_size: 524_288,
            packet_fountain_reorg_risk_score_bps: 6_200,
            submitted_at_slot: DEVNET_SLOT + 18,
        })
        .expect("demo signal");
    state
        .submit_attestation(SubmitAttestationRequest {
            signal_id: signal,
            verdict: AttestationVerdict::RequireDandelionPacketFountainReorgCoverage,
            attestor_commitment: "attestor:demo-dandelion-packet-fountain-reorg-insurance"
                .to_string(),
            pq_signature_root: devnet_root(
                "ml-dsa-signature",
                "demo-packet-fountain-reorg-pressure",
            ),
            pq_public_key_root: devnet_root(
                "ml-kem-public-key",
                "demo-packet-fountain-reorg-pressure",
            ),
            transcript_root: devnet_root("transcript", "demo-packet-fountain-reorg-pressure"),
            quorum_weight_bps: 7_200,
            pq_security_bits: 256,
            observed_packet_fountain_reorg_risk_score_bps: 6_400,
            observed_privacy_set_size: 524_288,
            attested_at_slot: DEVNET_SLOT + 19,
        })
        .expect("demo attestation");
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn ensure_capacity(current: usize, max: usize, label: &str) -> Result<()> {
    if current >= max {
        return Err(format!("{label} capacity exceeded"));
    }
    Ok(())
}

fn ensure_non_empty(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> Result<()> {
    if value > MAX_BPS {
        return Err(format!("{label} exceeds {MAX_BPS} bps"));
    }
    Ok(())
}

fn stable_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&domain_hash(domain, parts, 32)),
        ],
        32,
    )
}

fn object_root<T: Serialize>(domain: &str, value: &T) -> String {
    let value = serde_json::to_value(value).expect("serializable runtime object");
    domain_hash(
        &format!("bridge-dandelion-packet-fountain-reorg-insurance:{domain}"),
        &[HashPart::Json(&value)],
        32,
    )
}

fn map_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": value,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("bridge-dandelion-packet-fountain-reorg-insurance:{domain}"),
        &leaves,
    )
}

fn devnet_root(domain: &str, label: &str) -> String {
    domain_hash(
        &format!("bridge-dandelion-packet-fountain-reorg-insurance:devnet:{domain}"),
        &[HashPart::Str(label), HashPart::Str(PROTOCOL_VERSION)],
        32,
    )
}
