use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialBridgeViewkeyQuarantineFirewallRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-bridge-viewkey-quarantine-firewall-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_BRIDGE_VIEWKEY_QUARANTINE_FIREWALL_RUNTIME_PROTOCOL_VERSION:
    &str = PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_FIREWALL_SUITE: &str = "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f";
pub const FIREWALL_SUITE: &str = "confidential-monero-bridge-viewkey-quarantine-root-v1";
pub const SIGNAL_SUITE: &str = "viewkey-leak-signal-commitment-root-v1";
pub const REBATE_SUITE: &str = "viewkey-quarantine-low-fee-rebate-root-v1";
pub const REDACTION_SUITE: &str = "operator-safe-viewkey-firewall-redaction-root-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_BRIDGE_ASSET_ID: &str = "xmr-confidential-bridge-note-devnet";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_SIGNAL_WINDOW_SLOTS: u64 = 96;
pub const DEFAULT_QUARANTINE_WINDOW_SLOTS: u64 = 720;
pub const DEFAULT_MAX_PUBLIC_REDACTION_BYTES: u64 = 2_048;
pub const DEFAULT_MIN_ATTESTATION_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_ATTESTATION_QUORUM_BPS: u64 = 8_400;
pub const DEFAULT_MAX_QUARANTINE_FEE_BPS: u64 = 18;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 7;
pub const DEFAULT_MIN_WATCHED_OUTPUTS: u64 = 512;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_POLICIES: usize = 524_288;
pub const MAX_COHORTS: usize = 1_048_576;
pub const MAX_SIGNALS: usize = 2_097_152;
pub const MAX_ATTESTATIONS: usize = 4_194_304;
pub const MAX_DECISIONS: usize = 2_097_152;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_REDACTION_BUDGETS: usize = 524_288;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const DEVNET_EPOCH: u64 = 8_032;
pub const DEVNET_SLOT: u64 = 288;
pub const DEVNET_L2_HEIGHT: u64 = 3_456_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallScope {
    DepositViewKey,
    WithdrawalViewKey,
    FastExitViewKey,
    ReserveAuditViewKey,
    LiquidityMirrorViewKey,
    WatchtowerEvidenceViewKey,
    MerchantPaymentViewKey,
    EmergencyExitViewKey,
}

impl FirewallScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositViewKey => "deposit_view_key",
            Self::WithdrawalViewKey => "withdrawal_view_key",
            Self::FastExitViewKey => "fast_exit_view_key",
            Self::ReserveAuditViewKey => "reserve_audit_view_key",
            Self::LiquidityMirrorViewKey => "liquidity_mirror_view_key",
            Self::WatchtowerEvidenceViewKey => "watchtower_evidence_view_key",
            Self::MerchantPaymentViewKey => "merchant_payment_view_key",
            Self::EmergencyExitViewKey => "emergency_exit_view_key",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallMode {
    Observe,
    RateLimit,
    QuarantineNewReceipts,
    QuarantineAllReceipts,
    RotateViewKey,
    EmergencyFreeze,
}

impl FirewallMode {
    pub fn severity(self) -> u64 {
        match self {
            Self::Observe => 1,
            Self::RateLimit => 2,
            Self::QuarantineNewReceipts => 3,
            Self::QuarantineAllReceipts => 4,
            Self::RotateViewKey => 5,
            Self::EmergencyFreeze => 6,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Active,
    Quarantined,
    Rotating,
    Frozen,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    ExcessiveScanDisclosure,
    SuspiciousViewKeyReuse,
    ReserveAuditMismatch,
    WatchtowerLeakReport,
    MerchantReceiptCorrelation,
    DandelionRouteCorrelation,
    KeyImageObservationSpike,
    EmergencyDisclosure,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalStatus {
    Submitted,
    Attested,
    Quarantined,
    Rotated,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    ConfirmLeak,
    ConfirmCorrelation,
    RequireRotation,
    RequireQuarantine,
    ClearFalsePositive,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionAction {
    Monitor,
    RateLimit,
    Quarantine,
    Rotate,
    Freeze,
    Release,
    Reject,
    Expire,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub hash_suite: String,
    pub pq_firewall_suite: String,
    pub firewall_suite: String,
    pub signal_suite: String,
    pub rebate_suite: String,
    pub redaction_suite: String,
    pub fee_asset_id: String,
    pub bridge_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub signal_window_slots: u64,
    pub quarantine_window_slots: u64,
    pub min_attestation_quorum_bps: u64,
    pub strong_attestation_quorum_bps: u64,
    pub max_quarantine_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub min_watched_outputs: u64,
    pub max_public_redaction_bytes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_firewall_suite: PQ_FIREWALL_SUITE.to_string(),
            firewall_suite: FIREWALL_SUITE.to_string(),
            signal_suite: SIGNAL_SUITE.to_string(),
            rebate_suite: REBATE_SUITE.to_string(),
            redaction_suite: REDACTION_SUITE.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            bridge_asset_id: DEFAULT_BRIDGE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            signal_window_slots: DEFAULT_SIGNAL_WINDOW_SLOTS,
            quarantine_window_slots: DEFAULT_QUARANTINE_WINDOW_SLOTS,
            min_attestation_quorum_bps: DEFAULT_MIN_ATTESTATION_QUORUM_BPS,
            strong_attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
            max_quarantine_fee_bps: DEFAULT_MAX_QUARANTINE_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            min_watched_outputs: DEFAULT_MIN_WATCHED_OUTPUTS,
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
    pub quarantine_decisions_published: u64,
    pub rotations_requested: u64,
    pub cohorts_quarantined: u64,
    pub cohorts_released: u64,
    pub rebates_published: u64,
    pub redaction_budgets_published: u64,
    pub operator_summaries_published: u64,
    pub leaked_signal_count: u64,
    pub rejected_signal_count: u64,
    pub live_quarantine_count: u64,
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
pub struct QuarantinePolicy {
    pub policy_id: String,
    pub scope: FirewallScope,
    pub mode: FirewallMode,
    pub owner_commitment: String,
    pub policy_commitment_root: String,
    pub allowed_viewkey_commitment_root: String,
    pub quarantine_fee_cap_bps: u64,
    pub min_privacy_set_size: u64,
    pub min_attestation_quorum_bps: u64,
    pub signal_window_slots: u64,
    pub quarantine_window_slots: u64,
    pub redaction_profile: String,
    pub active: bool,
    pub created_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisterPolicyRequest {
    pub scope: FirewallScope,
    pub mode: FirewallMode,
    pub owner_commitment: String,
    pub policy_commitment_root: String,
    pub allowed_viewkey_commitment_root: String,
    pub quarantine_fee_cap_bps: u64,
    pub min_privacy_set_size: u64,
    pub min_attestation_quorum_bps: u64,
    pub signal_window_slots: u64,
    pub quarantine_window_slots: u64,
    pub redaction_profile: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ViewKeyCohort {
    pub cohort_id: String,
    pub policy_id: String,
    pub scope: FirewallScope,
    pub status: CohortStatus,
    pub viewkey_commitment_root: String,
    pub output_set_commitment_root: String,
    pub key_image_domain_root: String,
    pub bridge_lane_id: String,
    pub watched_output_count: u64,
    pub privacy_set_size: u64,
    pub quarantine_fee_bps: u64,
    pub rotation_epoch: u64,
    pub active_signal_count: u64,
    pub quarantined_until_slot: u64,
    pub public_hint_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisterCohortRequest {
    pub policy_id: String,
    pub viewkey_commitment_root: String,
    pub output_set_commitment_root: String,
    pub key_image_domain_root: String,
    pub bridge_lane_id: String,
    pub watched_output_count: u64,
    pub privacy_set_size: u64,
    pub quarantine_fee_bps: u64,
    pub rotation_epoch: u64,
    pub public_hint_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ViewKeySignal {
    pub signal_id: String,
    pub cohort_id: String,
    pub policy_id: String,
    pub kind: SignalKind,
    pub status: SignalStatus,
    pub signal_commitment_root: String,
    pub evidence_root: String,
    pub key_image_observation_root: String,
    pub reporter_commitment: String,
    pub affected_output_count: u64,
    pub privacy_set_size: u64,
    pub leak_score_bps: u64,
    pub disclosure_bytes: u64,
    pub submitted_at_slot: u64,
    pub expires_at_slot: u64,
    pub attestation_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubmitSignalRequest {
    pub cohort_id: String,
    pub kind: SignalKind,
    pub signal_commitment_root: String,
    pub evidence_root: String,
    pub key_image_observation_root: String,
    pub reporter_commitment: String,
    pub affected_output_count: u64,
    pub privacy_set_size: u64,
    pub leak_score_bps: u64,
    pub disclosure_bytes: u64,
    pub submitted_at_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqFirewallAttestation {
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
    pub observed_leak_score_bps: u64,
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
    pub observed_leak_score_bps: u64,
    pub observed_privacy_set_size: u64,
    pub attested_at_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QuarantineDecision {
    pub decision_id: String,
    pub signal_id: String,
    pub cohort_id: String,
    pub policy_id: String,
    pub action: DecisionAction,
    pub decision_root: String,
    pub fee_rebate_commitment_root: String,
    pub replacement_viewkey_commitment_root: String,
    pub quarantined_until_slot: u64,
    pub paused_receipt_count: u64,
    pub released_receipt_count: u64,
    pub rebate_bps: u64,
    pub decided_at_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettleDecisionRequest {
    pub signal_id: String,
    pub action: DecisionAction,
    pub decision_root: String,
    pub fee_rebate_commitment_root: String,
    pub replacement_viewkey_commitment_root: String,
    pub paused_receipt_count: u64,
    pub released_receipt_count: u64,
    pub rebate_bps: u64,
    pub decided_at_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeRebate {
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
    pub scope: FirewallScope,
    pub cohort_id: String,
    pub public_hint_root: String,
    pub max_public_bytes: u64,
    pub consumed_public_bytes: u64,
    pub privacy_set_size: u64,
    pub expires_at_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishRedactionBudgetRequest {
    pub scope: FirewallScope,
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
    pub live_signal_count: u64,
    pub live_quarantine_count: u64,
    pub rotation_request_count: u64,
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
    pub policies: BTreeMap<String, QuarantinePolicy>,
    pub cohorts: BTreeMap<String, ViewKeyCohort>,
    pub signals: BTreeMap<String, ViewKeySignal>,
    pub attestations: BTreeMap<String, PqFirewallAttestation>,
    pub decisions: BTreeMap<String, QuarantineDecision>,
    pub rebates: BTreeMap<String, LowFeeRebate>,
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

        let deposit_policy = state
            .register_policy(RegisterPolicyRequest {
                scope: FirewallScope::DepositViewKey,
                mode: FirewallMode::QuarantineNewReceipts,
                owner_commitment: "owner:bridge-viewkey-council-a".to_string(),
                policy_commitment_root: devnet_root("policy", "deposit-viewkey-firewall"),
                allowed_viewkey_commitment_root: devnet_root("allowlist", "deposit-viewkeys"),
                quarantine_fee_cap_bps: 14,
                min_privacy_set_size: 262_144,
                min_attestation_quorum_bps: 7_200,
                signal_window_slots: 96,
                quarantine_window_slots: 720,
                redaction_profile: "deposit-viewkey-redacted-operator-profile".to_string(),
            })
            .expect("devnet deposit policy");
        let withdrawal_policy = state
            .register_policy(RegisterPolicyRequest {
                scope: FirewallScope::WithdrawalViewKey,
                mode: FirewallMode::RotateViewKey,
                owner_commitment: "owner:withdrawal-viewkey-council-b".to_string(),
                policy_commitment_root: devnet_root("policy", "withdrawal-viewkey-rotation"),
                allowed_viewkey_commitment_root: devnet_root("allowlist", "withdrawal-viewkeys"),
                quarantine_fee_cap_bps: 16,
                min_privacy_set_size: 393_216,
                min_attestation_quorum_bps: 7_600,
                signal_window_slots: 80,
                quarantine_window_slots: 960,
                redaction_profile: "withdrawal-viewkey-rotation-profile".to_string(),
            })
            .expect("devnet withdrawal policy");

        let deposit_cohort = state
            .register_cohort(RegisterCohortRequest {
                policy_id: deposit_policy,
                viewkey_commitment_root: devnet_root("viewkey", "deposit-cohort-alpha"),
                output_set_commitment_root: devnet_root("outputs", "deposit-cohort-alpha"),
                key_image_domain_root: devnet_root("key-images", "deposit-cohort-alpha"),
                bridge_lane_id: "deposit-lane-alpha".to_string(),
                watched_output_count: 8_192,
                privacy_set_size: 262_144,
                quarantine_fee_bps: 9,
                rotation_epoch: DEVNET_EPOCH,
                public_hint_root: devnet_root("hint", "deposit-cohort-alpha"),
            })
            .expect("devnet deposit cohort");
        let withdrawal_cohort = state
            .register_cohort(RegisterCohortRequest {
                policy_id: withdrawal_policy,
                viewkey_commitment_root: devnet_root("viewkey", "withdrawal-cohort-beta"),
                output_set_commitment_root: devnet_root("outputs", "withdrawal-cohort-beta"),
                key_image_domain_root: devnet_root("key-images", "withdrawal-cohort-beta"),
                bridge_lane_id: "withdrawal-lane-beta".to_string(),
                watched_output_count: 13_312,
                privacy_set_size: 524_288,
                quarantine_fee_bps: 11,
                rotation_epoch: DEVNET_EPOCH + 1,
                public_hint_root: devnet_root("hint", "withdrawal-cohort-beta"),
            })
            .expect("devnet withdrawal cohort");

        let signal = state
            .submit_signal(SubmitSignalRequest {
                cohort_id: deposit_cohort,
                kind: SignalKind::KeyImageObservationSpike,
                signal_commitment_root: devnet_root("signal", "deposit-key-image-spike"),
                evidence_root: devnet_root("evidence", "deposit-key-image-spike"),
                key_image_observation_root: devnet_root(
                    "key-image-observation",
                    "deposit-key-image-spike",
                ),
                reporter_commitment: "reporter:watchtower-cluster-13".to_string(),
                affected_output_count: 96,
                privacy_set_size: 262_144,
                leak_score_bps: 6_900,
                disclosure_bytes: 384,
                submitted_at_slot: DEVNET_SLOT,
            })
            .expect("devnet signal");
        state
            .submit_attestation(SubmitAttestationRequest {
                signal_id: signal.clone(),
                verdict: AttestationVerdict::RequireQuarantine,
                attestor_commitment: "attestor:pq-firewall-a".to_string(),
                pq_signature_root: devnet_root("ml-dsa-signature", "deposit-signal-a"),
                pq_public_key_root: devnet_root("ml-kem-public-key", "deposit-signal-a"),
                transcript_root: devnet_root("transcript", "deposit-signal-a"),
                quorum_weight_bps: 7_300,
                pq_security_bits: 256,
                observed_leak_score_bps: 7_100,
                observed_privacy_set_size: 262_144,
                attested_at_slot: DEVNET_SLOT + 2,
            })
            .expect("devnet attestation a");
        state
            .submit_attestation(SubmitAttestationRequest {
                signal_id: signal.clone(),
                verdict: AttestationVerdict::ConfirmLeak,
                attestor_commitment: "attestor:pq-firewall-b".to_string(),
                pq_signature_root: devnet_root("slh-dsa-signature", "deposit-signal-b"),
                pq_public_key_root: devnet_root("ml-kem-public-key", "deposit-signal-b"),
                transcript_root: devnet_root("transcript", "deposit-signal-b"),
                quorum_weight_bps: 8_600,
                pq_security_bits: 256,
                observed_leak_score_bps: 7_400,
                observed_privacy_set_size: 262_144,
                attested_at_slot: DEVNET_SLOT + 3,
            })
            .expect("devnet attestation b");
        let decision = state
            .settle_decision(SettleDecisionRequest {
                signal_id: signal,
                action: DecisionAction::Quarantine,
                decision_root: devnet_root("decision", "deposit-quarantine"),
                fee_rebate_commitment_root: devnet_root("rebate-commitment", "deposit-quarantine"),
                replacement_viewkey_commitment_root: devnet_root(
                    "replacement-viewkey",
                    "deposit-quarantine",
                ),
                paused_receipt_count: 48,
                released_receipt_count: 0,
                rebate_bps: 7,
                decided_at_slot: DEVNET_SLOT + 5,
            })
            .expect("devnet quarantine decision");
        state
            .publish_rebate(PublishRebateRequest {
                decision_id: decision,
                recipient_commitment: "recipient:deposit-lane-fee-sponsor".to_string(),
                rebate_micro_units: 21_000,
                fee_saved_micro_units: 84_000,
                rebate_bps: 7,
                settlement_slot: DEVNET_SLOT + 6,
                rebate_root: devnet_root("rebate", "deposit-quarantine"),
            })
            .expect("devnet rebate");
        state
            .publish_redaction_budget(PublishRedactionBudgetRequest {
                scope: FirewallScope::DepositViewKey,
                cohort_id: withdrawal_cohort,
                public_hint_root: devnet_root("redaction-hint", "withdrawal-cohort-beta"),
                max_public_bytes: 1_536,
                consumed_public_bytes: 448,
                privacy_set_size: 524_288,
                expires_at_slot: DEVNET_SLOT + 720,
            })
            .expect("devnet redaction budget");
        state
            .publish_operator_summary(DEVNET_EPOCH, DEVNET_SLOT + 8, DEVNET_L2_HEIGHT)
            .expect("devnet operator summary");
        state
    }

    pub fn register_policy(&mut self, request: RegisterPolicyRequest) -> Result<String> {
        ensure_capacity(self.policies.len(), MAX_POLICIES, "quarantine policies")?;
        ensure_non_empty(&request.owner_commitment, "owner_commitment")?;
        ensure_non_empty(&request.policy_commitment_root, "policy_commitment_root")?;
        ensure_non_empty(
            &request.allowed_viewkey_commitment_root,
            "allowed_viewkey_commitment_root",
        )?;
        ensure_non_empty(&request.redaction_profile, "redaction_profile")?;
        ensure_bps(request.quarantine_fee_cap_bps, "quarantine_fee_cap_bps")?;
        ensure_bps(
            request.min_attestation_quorum_bps,
            "min_attestation_quorum_bps",
        )?;
        if request.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("policy privacy set size below runtime floor".to_string());
        }
        if request.signal_window_slots == 0 || request.quarantine_window_slots == 0 {
            return Err("policy windows must be non-zero".to_string());
        }
        let policy_id = stable_id(
            "viewkey-firewall-policy",
            &[
                HashPart::Str(request.scope.as_str()),
                HashPart::Str(&request.owner_commitment),
                HashPart::Str(&request.policy_commitment_root),
                HashPart::Str(&request.allowed_viewkey_commitment_root),
            ],
        );
        if self.policies.contains_key(&policy_id) {
            return Err(format!("quarantine policy {policy_id} already exists"));
        }
        self.policies.insert(
            policy_id.clone(),
            QuarantinePolicy {
                policy_id: policy_id.clone(),
                scope: request.scope,
                mode: request.mode,
                owner_commitment: request.owner_commitment,
                policy_commitment_root: request.policy_commitment_root,
                allowed_viewkey_commitment_root: request.allowed_viewkey_commitment_root,
                quarantine_fee_cap_bps: request.quarantine_fee_cap_bps,
                min_privacy_set_size: request.min_privacy_set_size,
                min_attestation_quorum_bps: request.min_attestation_quorum_bps,
                signal_window_slots: request.signal_window_slots,
                quarantine_window_slots: request.quarantine_window_slots,
                redaction_profile: request.redaction_profile,
                active: true,
                created_at_height: DEVNET_L2_HEIGHT,
            },
        );
        self.counters.policies_registered = self.counters.policies_registered.saturating_add(1);
        self.refresh_roots();
        Ok(policy_id)
    }

    pub fn register_cohort(&mut self, request: RegisterCohortRequest) -> Result<String> {
        ensure_capacity(self.cohorts.len(), MAX_COHORTS, "viewkey cohorts")?;
        let policy = self
            .policies
            .get(&request.policy_id)
            .ok_or_else(|| format!("unknown quarantine policy {}", request.policy_id))?;
        ensure_non_empty(&request.viewkey_commitment_root, "viewkey_commitment_root")?;
        ensure_non_empty(
            &request.output_set_commitment_root,
            "output_set_commitment_root",
        )?;
        ensure_non_empty(&request.key_image_domain_root, "key_image_domain_root")?;
        ensure_non_empty(&request.bridge_lane_id, "bridge_lane_id")?;
        ensure_non_empty(&request.public_hint_root, "public_hint_root")?;
        ensure_bps(request.quarantine_fee_bps, "quarantine_fee_bps")?;
        if request.quarantine_fee_bps > policy.quarantine_fee_cap_bps {
            return Err("cohort quarantine fee exceeds policy cap".to_string());
        }
        if request.watched_output_count < self.config.min_watched_outputs {
            return Err("cohort watched output count below runtime floor".to_string());
        }
        if request.privacy_set_size < policy.min_privacy_set_size {
            return Err("cohort privacy set size below policy floor".to_string());
        }
        let cohort_id = stable_id(
            "viewkey-firewall-cohort",
            &[
                HashPart::Str(&request.policy_id),
                HashPart::Str(&request.viewkey_commitment_root),
                HashPart::Str(&request.output_set_commitment_root),
                HashPart::Str(&request.bridge_lane_id),
            ],
        );
        if self.cohorts.contains_key(&cohort_id) {
            return Err(format!("viewkey cohort {cohort_id} already exists"));
        }
        self.cohorts.insert(
            cohort_id.clone(),
            ViewKeyCohort {
                cohort_id: cohort_id.clone(),
                policy_id: request.policy_id,
                scope: policy.scope,
                status: CohortStatus::Active,
                viewkey_commitment_root: request.viewkey_commitment_root,
                output_set_commitment_root: request.output_set_commitment_root,
                key_image_domain_root: request.key_image_domain_root,
                bridge_lane_id: request.bridge_lane_id,
                watched_output_count: request.watched_output_count,
                privacy_set_size: request.privacy_set_size,
                quarantine_fee_bps: request.quarantine_fee_bps,
                rotation_epoch: request.rotation_epoch,
                active_signal_count: 0,
                quarantined_until_slot: 0,
                public_hint_root: request.public_hint_root,
            },
        );
        self.counters.cohorts_registered = self.counters.cohorts_registered.saturating_add(1);
        self.refresh_roots();
        Ok(cohort_id)
    }

    pub fn submit_signal(&mut self, request: SubmitSignalRequest) -> Result<String> {
        ensure_capacity(self.signals.len(), MAX_SIGNALS, "viewkey signals")?;
        let cohort = self
            .cohorts
            .get(&request.cohort_id)
            .ok_or_else(|| format!("unknown viewkey cohort {}", request.cohort_id))?
            .clone();
        let policy = self
            .policies
            .get(&cohort.policy_id)
            .ok_or_else(|| format!("unknown quarantine policy {}", cohort.policy_id))?;
        ensure_non_empty(&request.signal_commitment_root, "signal_commitment_root")?;
        ensure_non_empty(&request.evidence_root, "evidence_root")?;
        ensure_non_empty(
            &request.key_image_observation_root,
            "key_image_observation_root",
        )?;
        ensure_non_empty(&request.reporter_commitment, "reporter_commitment")?;
        ensure_bps(request.leak_score_bps, "leak_score_bps")?;
        if request.privacy_set_size < policy.min_privacy_set_size {
            return Err("signal privacy set below policy floor".to_string());
        }
        if request.disclosure_bytes > self.config.max_public_redaction_bytes {
            return Err("signal disclosure exceeds runtime redaction cap".to_string());
        }
        let signal_id = stable_id(
            "viewkey-firewall-signal",
            &[
                HashPart::Str(&request.cohort_id),
                HashPart::Str(&request.signal_commitment_root),
                HashPart::Str(&request.evidence_root),
                HashPart::U64(request.submitted_at_slot),
            ],
        );
        if self.signals.contains_key(&signal_id) {
            return Err(format!("viewkey signal {signal_id} already exists"));
        }
        let expires_at_slot = request
            .submitted_at_slot
            .saturating_add(policy.signal_window_slots);
        self.signals.insert(
            signal_id.clone(),
            ViewKeySignal {
                signal_id: signal_id.clone(),
                cohort_id: request.cohort_id.clone(),
                policy_id: cohort.policy_id.clone(),
                kind: request.kind,
                status: SignalStatus::Submitted,
                signal_commitment_root: request.signal_commitment_root,
                evidence_root: request.evidence_root,
                key_image_observation_root: request.key_image_observation_root,
                reporter_commitment: request.reporter_commitment,
                affected_output_count: request.affected_output_count,
                privacy_set_size: request.privacy_set_size,
                leak_score_bps: request.leak_score_bps,
                disclosure_bytes: request.disclosure_bytes,
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
            "viewkey firewall attestations",
        )?;
        let signal = self
            .signals
            .get(&request.signal_id)
            .ok_or_else(|| format!("unknown viewkey signal {}", request.signal_id))?
            .clone();
        let policy = self
            .policies
            .get(&signal.policy_id)
            .ok_or_else(|| format!("unknown quarantine policy {}", signal.policy_id))?;
        ensure_non_empty(&request.attestor_commitment, "attestor_commitment")?;
        ensure_non_empty(&request.pq_signature_root, "pq_signature_root")?;
        ensure_non_empty(&request.pq_public_key_root, "pq_public_key_root")?;
        ensure_non_empty(&request.transcript_root, "transcript_root")?;
        ensure_bps(request.quorum_weight_bps, "quorum_weight_bps")?;
        ensure_bps(request.observed_leak_score_bps, "observed_leak_score_bps")?;
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
            "viewkey-firewall-attestation",
            &[
                HashPart::Str(&request.signal_id),
                HashPart::Str(&request.attestor_commitment),
                HashPart::Str(&request.pq_signature_root),
                HashPart::U64(request.attested_at_slot),
            ],
        );
        if self.attestations.contains_key(&attestation_id) {
            return Err(format!(
                "viewkey firewall attestation {attestation_id} already exists"
            ));
        }
        self.attestations.insert(
            attestation_id.clone(),
            PqFirewallAttestation {
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
                observed_leak_score_bps: request.observed_leak_score_bps,
                observed_privacy_set_size: request.observed_privacy_set_size,
                attested_at_slot: request.attested_at_slot,
            },
        );
        if let Some(signal) = self.signals.get_mut(&request.signal_id) {
            signal.attestation_ids.insert(attestation_id.clone());
            signal.status = match request.verdict {
                AttestationVerdict::ClearFalsePositive => SignalStatus::Attested,
                _ => SignalStatus::Attested,
            };
        }
        self.counters.attestations_recorded = self.counters.attestations_recorded.saturating_add(1);
        if matches!(
            request.verdict,
            AttestationVerdict::ConfirmLeak
                | AttestationVerdict::ConfirmCorrelation
                | AttestationVerdict::RequireQuarantine
        ) {
            self.counters.leaked_signal_count = self.counters.leaked_signal_count.saturating_add(1);
        }
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn settle_decision(&mut self, request: SettleDecisionRequest) -> Result<String> {
        ensure_capacity(
            self.decisions.len(),
            MAX_DECISIONS,
            "viewkey quarantine decisions",
        )?;
        let signal = self
            .signals
            .get(&request.signal_id)
            .ok_or_else(|| format!("unknown viewkey signal {}", request.signal_id))?
            .clone();
        let policy = self
            .policies
            .get(&signal.policy_id)
            .ok_or_else(|| format!("unknown quarantine policy {}", signal.policy_id))?;
        ensure_non_empty(&request.decision_root, "decision_root")?;
        ensure_non_empty(
            &request.fee_rebate_commitment_root,
            "fee_rebate_commitment_root",
        )?;
        ensure_non_empty(
            &request.replacement_viewkey_commitment_root,
            "replacement_viewkey_commitment_root",
        )?;
        ensure_bps(request.rebate_bps, "rebate_bps")?;
        if request.rebate_bps > self.config.target_rebate_bps.saturating_mul(2) {
            return Err("decision rebate exceeds runtime ceiling".to_string());
        }
        let quarantined_until_slot = match request.action {
            DecisionAction::Quarantine | DecisionAction::Freeze => request
                .decided_at_slot
                .saturating_add(policy.quarantine_window_slots),
            DecisionAction::Rotate => request
                .decided_at_slot
                .saturating_add(policy.quarantine_window_slots / 2),
            _ => 0,
        };
        let decision_id = stable_id(
            "viewkey-firewall-decision",
            &[
                HashPart::Str(&request.signal_id),
                HashPart::Str(&request.decision_root),
                HashPart::U64(request.decided_at_slot),
            ],
        );
        if self.decisions.contains_key(&decision_id) {
            return Err(format!("viewkey decision {decision_id} already exists"));
        }
        self.decisions.insert(
            decision_id.clone(),
            QuarantineDecision {
                decision_id: decision_id.clone(),
                signal_id: request.signal_id.clone(),
                cohort_id: signal.cohort_id.clone(),
                policy_id: signal.policy_id.clone(),
                action: request.action,
                decision_root: request.decision_root,
                fee_rebate_commitment_root: request.fee_rebate_commitment_root,
                replacement_viewkey_commitment_root: request.replacement_viewkey_commitment_root,
                quarantined_until_slot,
                paused_receipt_count: request.paused_receipt_count,
                released_receipt_count: request.released_receipt_count,
                rebate_bps: request.rebate_bps,
                decided_at_slot: request.decided_at_slot,
            },
        );
        if let Some(signal) = self.signals.get_mut(&request.signal_id) {
            signal.status = match request.action {
                DecisionAction::Quarantine | DecisionAction::Freeze => SignalStatus::Quarantined,
                DecisionAction::Rotate => SignalStatus::Rotated,
                DecisionAction::Reject => SignalStatus::Rejected,
                DecisionAction::Expire => SignalStatus::Expired,
                _ => SignalStatus::Attested,
            };
        }
        if let Some(cohort) = self.cohorts.get_mut(&signal.cohort_id) {
            match request.action {
                DecisionAction::Quarantine => {
                    cohort.status = CohortStatus::Quarantined;
                    cohort.quarantined_until_slot = quarantined_until_slot;
                    self.counters.cohorts_quarantined =
                        self.counters.cohorts_quarantined.saturating_add(1);
                }
                DecisionAction::Freeze => {
                    cohort.status = CohortStatus::Frozen;
                    cohort.quarantined_until_slot = quarantined_until_slot;
                    self.counters.cohorts_quarantined =
                        self.counters.cohorts_quarantined.saturating_add(1);
                }
                DecisionAction::Rotate => {
                    cohort.status = CohortStatus::Rotating;
                    cohort.rotation_epoch = cohort.rotation_epoch.saturating_add(1);
                    cohort.quarantined_until_slot = quarantined_until_slot;
                    self.counters.rotations_requested =
                        self.counters.rotations_requested.saturating_add(1);
                }
                DecisionAction::Release => {
                    cohort.status = CohortStatus::Active;
                    cohort.quarantined_until_slot = 0;
                    self.counters.cohorts_released =
                        self.counters.cohorts_released.saturating_add(1);
                }
                DecisionAction::Reject => {
                    self.counters.rejected_signal_count =
                        self.counters.rejected_signal_count.saturating_add(1);
                }
                _ => {}
            }
        }
        self.counters.quarantine_decisions_published = self
            .counters
            .quarantine_decisions_published
            .saturating_add(1);
        self.refresh_live_counts();
        self.refresh_roots();
        Ok(decision_id)
    }

    pub fn publish_rebate(&mut self, request: PublishRebateRequest) -> Result<String> {
        ensure_capacity(
            self.rebates.len(),
            MAX_REBATES,
            "viewkey quarantine rebates",
        )?;
        let decision = self
            .decisions
            .get(&request.decision_id)
            .ok_or_else(|| format!("unknown viewkey decision {}", request.decision_id))?;
        ensure_non_empty(&request.recipient_commitment, "recipient_commitment")?;
        ensure_non_empty(&request.rebate_root, "rebate_root")?;
        ensure_bps(request.rebate_bps, "rebate_bps")?;
        let rebate_id = stable_id(
            "viewkey-firewall-rebate",
            &[
                HashPart::Str(&request.decision_id),
                HashPart::Str(&request.recipient_commitment),
                HashPart::U64(request.settlement_slot),
            ],
        );
        if self.rebates.contains_key(&rebate_id) {
            return Err(format!("viewkey rebate {rebate_id} already exists"));
        }
        self.rebates.insert(
            rebate_id.clone(),
            LowFeeRebate {
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
            "viewkey redaction budgets",
        )?;
        ensure_non_empty(&request.cohort_id, "cohort_id")?;
        ensure_non_empty(&request.public_hint_root, "public_hint_root")?;
        if !self.cohorts.contains_key(&request.cohort_id) {
            return Err(format!("unknown viewkey cohort {}", request.cohort_id));
        }
        if request.consumed_public_bytes > request.max_public_bytes {
            return Err("redaction budget consumed bytes exceed max".to_string());
        }
        if request.max_public_bytes > self.config.max_public_redaction_bytes {
            return Err("redaction budget exceeds runtime public byte cap".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("redaction budget privacy set below runtime floor".to_string());
        }
        let budget_id = stable_id(
            "viewkey-firewall-redaction-budget",
            &[
                HashPart::Str(request.scope.as_str()),
                HashPart::Str(&request.cohort_id),
                HashPart::Str(&request.public_hint_root),
                HashPart::U64(request.expires_at_slot),
            ],
        );
        if self.redaction_budgets.contains_key(&budget_id) {
            return Err(format!(
                "viewkey redaction budget {budget_id} already exists"
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
            "viewkey firewall operator summaries",
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
            .filter(|cohort| matches!(cohort.status, CohortStatus::Active | CohortStatus::Rotating))
            .count() as u64;
        let live_signal_count = self
            .signals
            .values()
            .filter(|signal| {
                matches!(
                    signal.status,
                    SignalStatus::Submitted | SignalStatus::Attested | SignalStatus::Quarantined
                )
            })
            .count() as u64;
        let summary_id = stable_id(
            "viewkey-firewall-operator-summary",
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
                live_signal_count,
                live_quarantine_count: self.counters.live_quarantine_count,
                rotation_request_count: self.counters.rotations_requested,
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
        self.counters.live_quarantine_count = self
            .cohorts
            .values()
            .filter(|cohort| {
                matches!(
                    cohort.status,
                    CohortStatus::Quarantined | CohortStatus::Frozen
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
            "bridge-viewkey-quarantine-firewall:state",
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
            "pq_firewall_suite": self.config.pq_firewall_suite,
            "firewall_suite": self.config.firewall_suite,
            "signal_suite": self.config.signal_suite,
            "rebate_suite": self.config.rebate_suite,
            "redaction_suite": self.config.redaction_suite,
            "fee_asset_id": self.config.fee_asset_id,
            "bridge_asset_id": self.config.bridge_asset_id,
            "min_privacy_set_size": self.config.min_privacy_set_size,
            "target_privacy_set_size": self.config.target_privacy_set_size,
            "min_pq_security_bits": self.config.min_pq_security_bits,
            "signal_window_slots": self.config.signal_window_slots,
            "quarantine_window_slots": self.config.quarantine_window_slots,
            "max_quarantine_fee_bps": self.config.max_quarantine_fee_bps,
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
                "mode": policy.mode,
                "quarantine_fee_cap_bps": policy.quarantine_fee_cap_bps,
                "min_privacy_set_size": policy.min_privacy_set_size,
                "min_attestation_quorum_bps": policy.min_attestation_quorum_bps,
                "signal_window_slots": policy.signal_window_slots,
                "quarantine_window_slots": policy.quarantine_window_slots,
                "active": policy.active,
            })).collect::<Vec<_>>(),
            "cohorts": self.cohorts.values().map(|cohort| json!({
                "cohort_id": cohort.cohort_id,
                "policy_id": cohort.policy_id,
                "scope": cohort.scope,
                "status": cohort.status,
                "bridge_lane_id": cohort.bridge_lane_id,
                "watched_output_count": cohort.watched_output_count,
                "privacy_set_size": cohort.privacy_set_size,
                "quarantine_fee_bps": cohort.quarantine_fee_bps,
                "rotation_epoch": cohort.rotation_epoch,
                "active_signal_count": cohort.active_signal_count,
                "quarantined_until_slot": cohort.quarantined_until_slot,
                "public_hint_root": cohort.public_hint_root,
            })).collect::<Vec<_>>(),
            "signals": self.signals.values().map(|signal| json!({
                "signal_id": signal.signal_id,
                "cohort_id": signal.cohort_id,
                "kind": signal.kind,
                "status": signal.status,
                "affected_output_count": signal.affected_output_count,
                "privacy_set_size": signal.privacy_set_size,
                "leak_score_bps": signal.leak_score_bps,
                "disclosure_bytes": signal.disclosure_bytes,
                "submitted_at_slot": signal.submitted_at_slot,
                "expires_at_slot": signal.expires_at_slot,
                "attestation_count": signal.attestation_ids.len(),
            })).collect::<Vec<_>>(),
            "decisions": self.decisions.values().map(|decision| json!({
                "decision_id": decision.decision_id,
                "signal_id": decision.signal_id,
                "cohort_id": decision.cohort_id,
                "action": decision.action,
                "quarantined_until_slot": decision.quarantined_until_slot,
                "paused_receipt_count": decision.paused_receipt_count,
                "released_receipt_count": decision.released_receipt_count,
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
    let signal = state
        .submit_signal(SubmitSignalRequest {
            cohort_id: state.cohorts.keys().next().cloned().unwrap_or_default(),
            kind: SignalKind::SuspiciousViewKeyReuse,
            signal_commitment_root: devnet_root("signal", "demo-viewkey-reuse"),
            evidence_root: devnet_root("evidence", "demo-viewkey-reuse"),
            key_image_observation_root: devnet_root("key-image-observation", "demo-viewkey-reuse"),
            reporter_commitment: "reporter:demo-wallet-scan-guard".to_string(),
            affected_output_count: 24,
            privacy_set_size: 262_144,
            leak_score_bps: 5_900,
            disclosure_bytes: 256,
            submitted_at_slot: DEVNET_SLOT + 18,
        })
        .expect("demo viewkey signal");
    state
        .submit_attestation(SubmitAttestationRequest {
            signal_id: signal,
            verdict: AttestationVerdict::RequireRotation,
            attestor_commitment: "attestor:demo-pq-firewall".to_string(),
            pq_signature_root: devnet_root("ml-dsa-signature", "demo-viewkey-reuse"),
            pq_public_key_root: devnet_root("ml-kem-public-key", "demo-viewkey-reuse"),
            transcript_root: devnet_root("transcript", "demo-viewkey-reuse"),
            quorum_weight_bps: 7_100,
            pq_security_bits: 256,
            observed_leak_score_bps: 6_050,
            observed_privacy_set_size: 262_144,
            attested_at_slot: DEVNET_SLOT + 19,
        })
        .expect("demo viewkey attestation");
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
        &format!("bridge-viewkey-quarantine-firewall:{domain}"),
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
        &format!("bridge-viewkey-quarantine-firewall:{domain}"),
        &leaves,
    )
}

fn devnet_root(domain: &str, label: &str) -> String {
    domain_hash(
        &format!("bridge-viewkey-quarantine-firewall:devnet:{domain}"),
        &[HashPart::Str(label), HashPart::Str(PROTOCOL_VERSION)],
        32,
    )
}
