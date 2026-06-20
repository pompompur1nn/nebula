use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateBulletproofsPlusBatchAuditRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_BULLETPROOFS_PLUS_BATCH_AUDIT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-bulletproofs-plus-batch-audit-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_BULLETPROOFS_PLUS_BATCH_AUDIT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 1_024_000;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const BULLETPROOFS_PLUS_AUDIT_SCHEME: &str =
    "monero-bulletproofs-plus-batch-audit-transcript-root-v1";
pub const RANGE_PROOF_TRANSCRIPT_SCHEME: &str =
    "range-proof-transcript-roots-only-no-proof-bytes-v1";
pub const PQ_AUDITOR_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-bulletproofs-plus-auditor-attestation-v1";
pub const VIEWKEY_REDACTION_SCHEME: &str = "view-key-safe-redaction-root-v1";
pub const RING_DECOY_FLOOR_SCHEME: &str = "monero-ring-decoy-privacy-floor-root-v1";
pub const FEE_SPONSORED_BATCH_SCHEME: &str =
    "low-fee-sponsored-bulletproofs-plus-audit-batch-root-v1";
pub const ANOMALY_QUARANTINE_SCHEME: &str = "bulletproofs-plus-audit-anomaly-quarantine-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "operator-safe-bulletproofs-plus-audit-summary-root-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_amounts_addresses_view_keys_key_images_decoy_graphs_or_proof_bytes";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_RING_SIZE: u64 = 16;
pub const DEFAULT_MIN_DECOY_SET_SIZE: u64 = 128;
pub const DEFAULT_MIN_DECOY_AGE_BUCKETS: u64 = 8;
pub const DEFAULT_MIN_BATCH_PROOFS: u64 = 8;
pub const DEFAULT_MAX_BATCH_PROOFS: u64 = 512;
pub const DEFAULT_TARGET_BATCH_PROOFS: u64 = 128;
pub const DEFAULT_MIN_OUTPUT_COMMITMENTS: u64 = 16;
pub const DEFAULT_MAX_WINDOW_BLOCKS: u64 = 72;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_AUDITOR_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_AUDITOR_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 6;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_250;
pub const DEFAULT_REBATE_BPS: u64 = 4;
pub const DEFAULT_ANOMALY_THRESHOLD_BPS: u64 = 125;
pub const DEFAULT_OPERATOR_SUMMARY_BUCKET_SIZE: u64 = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditWindowStatus {
    Open,
    IntakeClosed,
    TranscriptRooted,
    PrivacyFloored,
    Attesting,
    Attested,
    Sponsored,
    Published,
    Quarantined,
    Rejected,
    Expired,
}

impl AuditWindowStatus {
    pub fn accepts_transcripts(self) -> bool {
        matches!(self, Self::Open | Self::IntakeClosed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptStatus {
    Submitted,
    Rooted,
    Redacted,
    PrivacyChecked,
    Batched,
    Quarantined,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Quorum,
    StrongQuorum,
    Expired,
    Revoked,
    Rejected,
}

impl AttestationStatus {
    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Accepted | Self::Quorum | Self::StrongQuorum)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionStatus {
    Planned,
    Applied,
    OperatorSafe,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyFloorStatus {
    Pending,
    Passed,
    NeedsMoreDecoys,
    NeedsRingExpansion,
    NeedsAgeDiversity,
    Quarantined,
}

impl PrivacyFloorStatus {
    pub fn passed(self) -> bool {
        matches!(self, Self::Passed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsoredBatchStatus {
    Open,
    Reserved,
    Applied,
    Published,
    Exhausted,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyKind {
    TranscriptMismatch,
    RangeProofRootDrift,
    LowDecoyDiversity,
    RingReuseSignal,
    ViewKeyLeakage,
    AuditorEquivocation,
    SponsorExhaustion,
    OperatorSummaryLeakage,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalySeverity {
    Watch,
    Elevated,
    Critical,
    Halt,
}

impl AnomalySeverity {
    pub fn quarantines(self) -> bool {
        matches!(self, Self::Critical | Self::Halt)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SummaryAudience {
    Operator,
    Auditor,
    Sponsor,
    Watchtower,
    Public,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub audit_scheme: String,
    pub transcript_scheme: String,
    pub pq_attestation_scheme: String,
    pub redaction_scheme: String,
    pub ring_decoy_floor_scheme: String,
    pub fee_sponsored_batch_scheme: String,
    pub anomaly_quarantine_scheme: String,
    pub operator_summary_scheme: String,
    pub privacy_boundary: String,
    pub min_ring_size: u64,
    pub min_decoy_set_size: u64,
    pub min_decoy_age_buckets: u64,
    pub min_batch_proofs: u64,
    pub target_batch_proofs: u64,
    pub max_batch_proofs: u64,
    pub min_output_commitments: u64,
    pub max_window_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub quarantine_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub auditor_quorum_bps: u64,
    pub strong_auditor_quorum_bps: u64,
    pub max_user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub rebate_bps: u64,
    pub anomaly_threshold_bps: u64,
    pub operator_summary_bucket_size: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            audit_scheme: BULLETPROOFS_PLUS_AUDIT_SCHEME.to_string(),
            transcript_scheme: RANGE_PROOF_TRANSCRIPT_SCHEME.to_string(),
            pq_attestation_scheme: PQ_AUDITOR_ATTESTATION_SCHEME.to_string(),
            redaction_scheme: VIEWKEY_REDACTION_SCHEME.to_string(),
            ring_decoy_floor_scheme: RING_DECOY_FLOOR_SCHEME.to_string(),
            fee_sponsored_batch_scheme: FEE_SPONSORED_BATCH_SCHEME.to_string(),
            anomaly_quarantine_scheme: ANOMALY_QUARANTINE_SCHEME.to_string(),
            operator_summary_scheme: OPERATOR_SUMMARY_SCHEME.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            min_decoy_set_size: DEFAULT_MIN_DECOY_SET_SIZE,
            min_decoy_age_buckets: DEFAULT_MIN_DECOY_AGE_BUCKETS,
            min_batch_proofs: DEFAULT_MIN_BATCH_PROOFS,
            target_batch_proofs: DEFAULT_TARGET_BATCH_PROOFS,
            max_batch_proofs: DEFAULT_MAX_BATCH_PROOFS,
            min_output_commitments: DEFAULT_MIN_OUTPUT_COMMITMENTS,
            max_window_blocks: DEFAULT_MAX_WINDOW_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            auditor_quorum_bps: DEFAULT_AUDITOR_QUORUM_BPS,
            strong_auditor_quorum_bps: DEFAULT_STRONG_AUDITOR_QUORUM_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            anomaly_threshold_bps: DEFAULT_ANOMALY_THRESHOLD_BPS,
            operator_summary_bucket_size: DEFAULT_OPERATOR_SUMMARY_BUCKET_SIZE,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_sequence: u64,
    pub windows: u64,
    pub transcripts: u64,
    pub attestations: u64,
    pub redactions: u64,
    pub privacy_floors: u64,
    pub sponsored_batches: u64,
    pub anomalies: u64,
    pub summaries: u64,
    pub quarantined_windows: u64,
    pub published_windows: u64,
    pub total_proofs_modeled: u64,
    pub total_outputs_modeled: u64,
    pub total_fee_piconero_modeled: u128,
    pub total_sponsor_piconero_modeled: u128,
}

impl Counters {
    pub fn next(&mut self) -> u64 {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        sequence
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub window_root: String,
    pub transcript_root: String,
    pub attestation_root: String,
    pub redaction_root: String,
    pub privacy_floor_root: String,
    pub sponsored_batch_root: String,
    pub anomaly_root: String,
    pub operator_summary_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            window_root: empty_root("BPP-AUDIT-WINDOW"),
            transcript_root: empty_root("BPP-AUDIT-TRANSCRIPT"),
            attestation_root: empty_root("BPP-AUDIT-ATTESTATION"),
            redaction_root: empty_root("BPP-AUDIT-REDACTION"),
            privacy_floor_root: empty_root("BPP-AUDIT-PRIVACY-FLOOR"),
            sponsored_batch_root: empty_root("BPP-AUDIT-SPONSORED-BATCH"),
            anomaly_root: empty_root("BPP-AUDIT-ANOMALY"),
            operator_summary_root: empty_root("BPP-AUDIT-OPERATOR-SUMMARY"),
            nullifier_root: empty_root("BPP-AUDIT-NULLIFIER"),
            public_record_root: empty_root("BPP-AUDIT-PUBLIC-RECORD"),
            state_root: empty_root("BPP-AUDIT-STATE"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditWindowRequest {
    pub coordinator_id: String,
    pub monero_height_start: u64,
    pub monero_height_end: u64,
    pub l2_height_opened: u64,
    pub transcript_intake_root: String,
    pub range_proof_manifest_root: String,
    pub output_commitment_root: String,
    pub ring_member_bucket_root: String,
    pub decoy_age_bucket_root: String,
    pub expected_proof_count: u64,
    pub expected_output_count: u64,
    pub max_user_fee_bps: u64,
    pub operator_hint_root: String,
    pub window_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditWindowRecord {
    pub window_id: String,
    pub sequence: u64,
    pub status: AuditWindowStatus,
    pub coordinator_id: String,
    pub monero_height_start: u64,
    pub monero_height_end: u64,
    pub l2_height_opened: u64,
    pub l2_height_closed: Option<u64>,
    pub transcript_intake_root: String,
    pub range_proof_manifest_root: String,
    pub output_commitment_root: String,
    pub ring_member_bucket_root: String,
    pub decoy_age_bucket_root: String,
    pub expected_proof_count: u64,
    pub expected_output_count: u64,
    pub observed_proof_count: u64,
    pub observed_output_count: u64,
    pub max_user_fee_bps: u64,
    pub operator_hint_root: String,
    pub window_nonce: String,
    pub latest_transcript_root: String,
    pub latest_privacy_floor_root: String,
    pub latest_attestation_root: String,
    pub latest_summary_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TranscriptIngestRequest {
    pub window_id: String,
    pub submitter_id: String,
    pub transcript_shard_root: String,
    pub range_proof_transcript_root: String,
    pub proof_commitment_root: String,
    pub output_commitment_root: String,
    pub bulletproofs_plus_domain_root: String,
    pub proof_count: u64,
    pub output_count: u64,
    pub batch_weight: u64,
    pub transcript_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TranscriptRecord {
    pub transcript_id: String,
    pub window_id: String,
    pub sequence: u64,
    pub status: TranscriptStatus,
    pub submitter_id: String,
    pub transcript_shard_root: String,
    pub range_proof_transcript_root: String,
    pub proof_commitment_root: String,
    pub output_commitment_root: String,
    pub bulletproofs_plus_domain_root: String,
    pub proof_count: u64,
    pub output_count: u64,
    pub batch_weight: u64,
    pub transcript_nonce: String,
    pub redaction_id: Option<String>,
    pub privacy_floor_id: Option<String>,
    pub sponsored_batch_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestationRequest {
    pub window_id: String,
    pub auditor_id: String,
    pub committee_id: String,
    pub l2_height: u64,
    pub auditor_weight_bps: u64,
    pub pq_security_bits: u16,
    pub transcript_root: String,
    pub privacy_floor_root: String,
    pub redaction_root: String,
    pub ml_dsa_signature_root: String,
    pub slh_dsa_signature_root: String,
    pub attestation_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestationRecord {
    pub attestation_id: String,
    pub window_id: String,
    pub sequence: u64,
    pub status: AttestationStatus,
    pub auditor_id: String,
    pub committee_id: String,
    pub l2_height: u64,
    pub expires_at_l2_height: u64,
    pub auditor_weight_bps: u64,
    pub pq_security_bits: u16,
    pub transcript_root: String,
    pub privacy_floor_root: String,
    pub redaction_root: String,
    pub ml_dsa_signature_root: String,
    pub slh_dsa_signature_root: String,
    pub attestation_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewKeyRedactionRequest {
    pub window_id: String,
    pub transcript_id: String,
    pub redactor_id: String,
    pub source_view_grant_root: String,
    pub redacted_view_tag_root: String,
    pub redacted_output_hint_root: String,
    pub redacted_key_image_hint_root: String,
    pub disclosure_policy_root: String,
    pub redaction_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewKeyRedactionRecord {
    pub redaction_id: String,
    pub window_id: String,
    pub transcript_id: String,
    pub sequence: u64,
    pub status: RedactionStatus,
    pub redactor_id: String,
    pub source_view_grant_root: String,
    pub redacted_view_tag_root: String,
    pub redacted_output_hint_root: String,
    pub redacted_key_image_hint_root: String,
    pub disclosure_policy_root: String,
    pub operator_safe_root: String,
    pub redaction_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFloorRequest {
    pub window_id: String,
    pub transcript_id: String,
    pub evaluator_id: String,
    pub ring_size_floor: u64,
    pub decoy_set_size: u64,
    pub decoy_age_bucket_count: u64,
    pub ring_member_bucket_root: String,
    pub decoy_distribution_root: String,
    pub ring_reuse_signal_root: String,
    pub floor_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFloorRecord {
    pub floor_id: String,
    pub window_id: String,
    pub transcript_id: String,
    pub sequence: u64,
    pub status: PrivacyFloorStatus,
    pub evaluator_id: String,
    pub ring_size_floor: u64,
    pub decoy_set_size: u64,
    pub decoy_age_bucket_count: u64,
    pub ring_member_bucket_root: String,
    pub decoy_distribution_root: String,
    pub ring_reuse_signal_root: String,
    pub floor_score_bps: u64,
    pub floor_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsoredBatchRequest {
    pub window_id: String,
    pub sponsor_id: String,
    pub transcript_ids: Vec<String>,
    pub fee_budget_piconero: u128,
    pub sponsor_cover_bps: u64,
    pub user_fee_bps: u64,
    pub rebate_bps: u64,
    pub settlement_root: String,
    pub sponsor_signature_root: String,
    pub batch_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsoredBatchRecord {
    pub batch_id: String,
    pub window_id: String,
    pub sequence: u64,
    pub status: SponsoredBatchStatus,
    pub sponsor_id: String,
    pub transcript_ids: Vec<String>,
    pub transcript_root: String,
    pub proof_count: u64,
    pub output_count: u64,
    pub fee_budget_piconero: u128,
    pub sponsor_cover_bps: u64,
    pub user_fee_bps: u64,
    pub rebate_bps: u64,
    pub modeled_user_fee_piconero: u128,
    pub modeled_sponsor_fee_piconero: u128,
    pub settlement_root: String,
    pub sponsor_signature_root: String,
    pub batch_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AnomalyQuarantineRequest {
    pub window_id: String,
    pub transcript_id: Option<String>,
    pub reporter_id: String,
    pub kind: AnomalyKind,
    pub severity: AnomalySeverity,
    pub evidence_root: String,
    pub mitigation_root: String,
    pub quarantine_nonce: String,
    pub l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AnomalyQuarantineRecord {
    pub anomaly_id: String,
    pub window_id: String,
    pub transcript_id: Option<String>,
    pub sequence: u64,
    pub reporter_id: String,
    pub kind: AnomalyKind,
    pub severity: AnomalySeverity,
    pub evidence_root: String,
    pub mitigation_root: String,
    pub quarantines_window: bool,
    pub l2_height: u64,
    pub expires_at_l2_height: u64,
    pub quarantine_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummaryRequest {
    pub window_id: String,
    pub producer_id: String,
    pub audience: SummaryAudience,
    pub bucketed_metrics_root: String,
    pub redacted_exception_root: String,
    pub fee_summary_root: String,
    pub privacy_floor_summary_root: String,
    pub summary_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummaryRecord {
    pub summary_id: String,
    pub window_id: String,
    pub sequence: u64,
    pub producer_id: String,
    pub audience: SummaryAudience,
    pub bucketed_metrics_root: String,
    pub redacted_exception_root: String,
    pub fee_summary_root: String,
    pub privacy_floor_summary_root: String,
    pub operator_safe_summary_root: String,
    pub proof_count_bucket: u64,
    pub output_count_bucket: u64,
    pub anomaly_count: u64,
    pub summary_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub windows: BTreeMap<String, AuditWindowRecord>,
    pub transcripts: BTreeMap<String, TranscriptRecord>,
    pub attestations: BTreeMap<String, PqAttestationRecord>,
    pub redactions: BTreeMap<String, ViewKeyRedactionRecord>,
    pub privacy_floors: BTreeMap<String, PrivacyFloorRecord>,
    pub sponsored_batches: BTreeMap<String, SponsoredBatchRecord>,
    pub anomalies: BTreeMap<String, AnomalyQuarantineRecord>,
    pub operator_summaries: BTreeMap<String, OperatorSummaryRecord>,
    pub nullifiers: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::devnet()).expect("devnet config is valid")
    }
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            windows: BTreeMap::new(),
            transcripts: BTreeMap::new(),
            attestations: BTreeMap::new(),
            redactions: BTreeMap::new(),
            privacy_floors: BTreeMap::new(),
            sponsored_batches: BTreeMap::new(),
            anomalies: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn open_audit_window(&mut self, request: AuditWindowRequest) -> Result<AuditWindowRecord> {
        require(
            request.monero_height_start <= request.monero_height_end,
            "invalid monero height range",
        )?;
        require(
            request.expected_proof_count >= self.config.min_batch_proofs,
            "expected proof count below batch floor",
        )?;
        let sequence = self.counters.next();
        let window_id = window_id(sequence, &request);
        require_unique(&mut self.nullifiers, "window", &window_id)?;
        let record = AuditWindowRecord {
            window_id: window_id.clone(),
            sequence,
            status: AuditWindowStatus::Open,
            coordinator_id: request.coordinator_id,
            monero_height_start: request.monero_height_start,
            monero_height_end: request.monero_height_end,
            l2_height_opened: request.l2_height_opened,
            l2_height_closed: None,
            transcript_intake_root: request.transcript_intake_root,
            range_proof_manifest_root: request.range_proof_manifest_root,
            output_commitment_root: request.output_commitment_root,
            ring_member_bucket_root: request.ring_member_bucket_root,
            decoy_age_bucket_root: request.decoy_age_bucket_root,
            expected_proof_count: request.expected_proof_count,
            expected_output_count: request.expected_output_count,
            observed_proof_count: 0,
            observed_output_count: 0,
            max_user_fee_bps: request.max_user_fee_bps,
            operator_hint_root: request.operator_hint_root,
            window_nonce: request.window_nonce,
            latest_transcript_root: empty_root("BPP-WINDOW-TRANSCRIPT"),
            latest_privacy_floor_root: empty_root("BPP-WINDOW-PRIVACY-FLOOR"),
            latest_attestation_root: empty_root("BPP-WINDOW-ATTESTATION"),
            latest_summary_root: empty_root("BPP-WINDOW-SUMMARY"),
        };
        self.counters.windows = self.counters.windows.saturating_add(1);
        self.windows.insert(window_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn ingest_transcript(
        &mut self,
        request: TranscriptIngestRequest,
    ) -> Result<TranscriptRecord> {
        let window = self
            .windows
            .get(&request.window_id)
            .ok_or_else(|| format!("unknown audit window {}", request.window_id))?;
        require(
            window.status.accepts_transcripts(),
            "window no longer accepts transcripts",
        )?;
        require(request.proof_count > 0, "transcript proof count is zero")?;
        let sequence = self.counters.next();
        let transcript_id = transcript_id(sequence, &request);
        require_unique(&mut self.nullifiers, "transcript", &transcript_id)?;
        let record = TranscriptRecord {
            transcript_id: transcript_id.clone(),
            window_id: request.window_id.clone(),
            sequence,
            status: TranscriptStatus::Rooted,
            submitter_id: request.submitter_id,
            transcript_shard_root: request.transcript_shard_root,
            range_proof_transcript_root: request.range_proof_transcript_root,
            proof_commitment_root: request.proof_commitment_root,
            output_commitment_root: request.output_commitment_root,
            bulletproofs_plus_domain_root: request.bulletproofs_plus_domain_root,
            proof_count: request.proof_count,
            output_count: request.output_count,
            batch_weight: request.batch_weight,
            transcript_nonce: request.transcript_nonce,
            redaction_id: None,
            privacy_floor_id: None,
            sponsored_batch_id: None,
        };
        self.counters.transcripts = self.counters.transcripts.saturating_add(1);
        self.counters.total_proofs_modeled = self
            .counters
            .total_proofs_modeled
            .saturating_add(record.proof_count);
        self.counters.total_outputs_modeled = self
            .counters
            .total_outputs_modeled
            .saturating_add(record.output_count);
        self.transcripts.insert(transcript_id, record.clone());
        self.recompute_window_observed_counts(&request.window_id);
        if let Some(window) = self.windows.get_mut(&request.window_id) {
            window.status = AuditWindowStatus::TranscriptRooted;
            window.latest_transcript_root = scoped_records_root(
                "BPP-WINDOW-TRANSCRIPT",
                &self.transcripts,
                &request.window_id,
            );
        }
        self.refresh_roots();
        Ok(record)
    }

    pub fn redact_viewkey_material(
        &mut self,
        request: ViewKeyRedactionRequest,
    ) -> Result<ViewKeyRedactionRecord> {
        require(
            self.windows.contains_key(&request.window_id),
            "unknown audit window",
        )?;
        require(
            self.transcripts.contains_key(&request.transcript_id),
            "unknown transcript",
        )?;
        let sequence = self.counters.next();
        let operator_safe_root = redaction_operator_safe_root(sequence, &request);
        let redaction_id = redaction_id(sequence, &request, &operator_safe_root);
        require_unique(&mut self.nullifiers, "redaction", &redaction_id)?;
        let record = ViewKeyRedactionRecord {
            redaction_id: redaction_id.clone(),
            window_id: request.window_id.clone(),
            transcript_id: request.transcript_id.clone(),
            sequence,
            status: RedactionStatus::OperatorSafe,
            redactor_id: request.redactor_id,
            source_view_grant_root: request.source_view_grant_root,
            redacted_view_tag_root: request.redacted_view_tag_root,
            redacted_output_hint_root: request.redacted_output_hint_root,
            redacted_key_image_hint_root: request.redacted_key_image_hint_root,
            disclosure_policy_root: request.disclosure_policy_root,
            operator_safe_root,
            redaction_nonce: request.redaction_nonce,
        };
        if let Some(transcript) = self.transcripts.get_mut(&request.transcript_id) {
            transcript.status = TranscriptStatus::Redacted;
            transcript.redaction_id = Some(redaction_id.clone());
        }
        self.counters.redactions = self.counters.redactions.saturating_add(1);
        self.redactions.insert(redaction_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn evaluate_privacy_floor(
        &mut self,
        request: PrivacyFloorRequest,
    ) -> Result<PrivacyFloorRecord> {
        require(
            self.windows.contains_key(&request.window_id),
            "unknown audit window",
        )?;
        require(
            self.transcripts.contains_key(&request.transcript_id),
            "unknown transcript",
        )?;
        let status = if request.ring_size_floor < self.config.min_ring_size {
            PrivacyFloorStatus::NeedsRingExpansion
        } else if request.decoy_set_size < self.config.min_decoy_set_size {
            PrivacyFloorStatus::NeedsMoreDecoys
        } else if request.decoy_age_bucket_count < self.config.min_decoy_age_buckets {
            PrivacyFloorStatus::NeedsAgeDiversity
        } else {
            PrivacyFloorStatus::Passed
        };
        let score_parts = [
            ratio_bps(request.ring_size_floor, self.config.min_ring_size),
            ratio_bps(request.decoy_set_size, self.config.min_decoy_set_size),
            ratio_bps(
                request.decoy_age_bucket_count,
                self.config.min_decoy_age_buckets,
            ),
        ];
        let floor_score_bps = score_parts.into_iter().min().unwrap_or(0).min(MAX_BPS);
        let sequence = self.counters.next();
        let floor_id = privacy_floor_id(sequence, &request, status, floor_score_bps);
        require_unique(&mut self.nullifiers, "privacy-floor", &floor_id)?;
        let record = PrivacyFloorRecord {
            floor_id: floor_id.clone(),
            window_id: request.window_id.clone(),
            transcript_id: request.transcript_id.clone(),
            sequence,
            status,
            evaluator_id: request.evaluator_id,
            ring_size_floor: request.ring_size_floor,
            decoy_set_size: request.decoy_set_size,
            decoy_age_bucket_count: request.decoy_age_bucket_count,
            ring_member_bucket_root: request.ring_member_bucket_root,
            decoy_distribution_root: request.decoy_distribution_root,
            ring_reuse_signal_root: request.ring_reuse_signal_root,
            floor_score_bps,
            floor_nonce: request.floor_nonce,
        };
        if let Some(transcript) = self.transcripts.get_mut(&request.transcript_id) {
            transcript.status = if status.passed() {
                TranscriptStatus::PrivacyChecked
            } else {
                TranscriptStatus::Quarantined
            };
            transcript.privacy_floor_id = Some(floor_id.clone());
        }
        if let Some(window) = self.windows.get_mut(&request.window_id) {
            window.status = if status.passed() {
                AuditWindowStatus::PrivacyFloored
            } else {
                AuditWindowStatus::Quarantined
            };
            window.latest_privacy_floor_root = scoped_privacy_floor_root(
                "BPP-WINDOW-PRIVACY-FLOOR",
                &self.privacy_floors,
                &request.window_id,
            );
        }
        if !status.passed() {
            self.counters.quarantined_windows = self.counters.quarantined_windows.saturating_add(1);
        }
        self.counters.privacy_floors = self.counters.privacy_floors.saturating_add(1);
        self.privacy_floors.insert(floor_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn attach_pq_attestation(
        &mut self,
        request: PqAttestationRequest,
    ) -> Result<PqAttestationRecord> {
        require(
            self.windows.contains_key(&request.window_id),
            "unknown audit window",
        )?;
        require(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "pq security bits below floor",
        )?;
        let sequence = self.counters.next();
        let attestation_id = attestation_id(sequence, &request);
        require_unique(&mut self.nullifiers, "attestation", &attestation_id)?;
        let mut record = PqAttestationRecord {
            attestation_id: attestation_id.clone(),
            window_id: request.window_id.clone(),
            sequence,
            status: AttestationStatus::Accepted,
            auditor_id: request.auditor_id,
            committee_id: request.committee_id,
            l2_height: request.l2_height,
            expires_at_l2_height: request
                .l2_height
                .saturating_add(self.config.attestation_ttl_blocks),
            auditor_weight_bps: request.auditor_weight_bps,
            pq_security_bits: request.pq_security_bits,
            transcript_root: request.transcript_root,
            privacy_floor_root: request.privacy_floor_root,
            redaction_root: request.redaction_root,
            ml_dsa_signature_root: request.ml_dsa_signature_root,
            slh_dsa_signature_root: request.slh_dsa_signature_root,
            attestation_nonce: request.attestation_nonce,
        };
        self.counters.attestations = self.counters.attestations.saturating_add(1);
        self.attestations
            .insert(attestation_id.clone(), record.clone());
        let quorum_bps = self.window_attestation_weight_bps(&request.window_id);
        record.status = if quorum_bps >= self.config.strong_auditor_quorum_bps {
            AttestationStatus::StrongQuorum
        } else if quorum_bps >= self.config.auditor_quorum_bps {
            AttestationStatus::Quorum
        } else {
            AttestationStatus::Accepted
        };
        self.attestations.insert(attestation_id, record.clone());
        if let Some(window) = self.windows.get_mut(&request.window_id) {
            window.status = if quorum_bps >= self.config.auditor_quorum_bps {
                AuditWindowStatus::Attested
            } else {
                AuditWindowStatus::Attesting
            };
            window.latest_attestation_root = scoped_attestation_root(
                "BPP-WINDOW-ATTESTATION",
                &self.attestations,
                &request.window_id,
            );
        }
        self.refresh_roots();
        Ok(record)
    }

    pub fn sponsor_audit_batch(
        &mut self,
        request: SponsoredBatchRequest,
    ) -> Result<SponsoredBatchRecord> {
        require(
            self.windows.contains_key(&request.window_id),
            "unknown audit window",
        )?;
        require(!request.transcript_ids.is_empty(), "empty sponsored batch")?;
        require(
            request.user_fee_bps <= self.config.max_user_fee_bps,
            "user fee above configured ceiling",
        )?;
        let mut proof_count = 0_u64;
        let mut output_count = 0_u64;
        let mut leaves = Vec::new();
        for transcript_id in &request.transcript_ids {
            let transcript = self
                .transcripts
                .get(transcript_id)
                .ok_or_else(|| format!("unknown transcript {transcript_id}"))?;
            require(
                transcript.window_id == request.window_id,
                "transcript window mismatch",
            )?;
            require(
                transcript.status == TranscriptStatus::PrivacyChecked
                    || transcript.status == TranscriptStatus::Redacted,
                "transcript is not sponsor eligible",
            )?;
            proof_count = proof_count.saturating_add(transcript.proof_count);
            output_count = output_count.saturating_add(transcript.output_count);
            leaves.push(json!(transcript_id));
        }
        require(
            proof_count >= self.config.min_batch_proofs,
            "sponsored proof count below floor",
        )?;
        let transcript_root = merkle_root("BPP-SPONSORED-BATCH-TRANSCRIPTS", &leaves);
        let modeled_base_fee = (proof_count as u128)
            .saturating_mul(1_000)
            .saturating_add((output_count as u128).saturating_mul(50));
        let modeled_user_fee_piconero =
            modeled_base_fee.saturating_mul(request.user_fee_bps as u128) / MAX_BPS as u128;
        let modeled_sponsor_fee_piconero =
            modeled_base_fee.saturating_mul(request.sponsor_cover_bps as u128) / MAX_BPS as u128;
        require(
            modeled_sponsor_fee_piconero <= request.fee_budget_piconero,
            "sponsor budget insufficient",
        )?;
        let sequence = self.counters.next();
        let batch_id = sponsored_batch_id(sequence, &request, &transcript_root);
        require_unique(&mut self.nullifiers, "sponsored-batch", &batch_id)?;
        let record = SponsoredBatchRecord {
            batch_id: batch_id.clone(),
            window_id: request.window_id.clone(),
            sequence,
            status: SponsoredBatchStatus::Applied,
            sponsor_id: request.sponsor_id,
            transcript_ids: request.transcript_ids.clone(),
            transcript_root,
            proof_count,
            output_count,
            fee_budget_piconero: request.fee_budget_piconero,
            sponsor_cover_bps: request.sponsor_cover_bps,
            user_fee_bps: request.user_fee_bps,
            rebate_bps: request.rebate_bps,
            modeled_user_fee_piconero,
            modeled_sponsor_fee_piconero,
            settlement_root: request.settlement_root,
            sponsor_signature_root: request.sponsor_signature_root,
            batch_nonce: request.batch_nonce,
        };
        for transcript_id in &request.transcript_ids {
            if let Some(transcript) = self.transcripts.get_mut(transcript_id) {
                transcript.status = TranscriptStatus::Batched;
                transcript.sponsored_batch_id = Some(batch_id.clone());
            }
        }
        if let Some(window) = self.windows.get_mut(&request.window_id) {
            window.status = AuditWindowStatus::Sponsored;
        }
        self.counters.sponsored_batches = self.counters.sponsored_batches.saturating_add(1);
        self.counters.total_fee_piconero_modeled = self
            .counters
            .total_fee_piconero_modeled
            .saturating_add(modeled_user_fee_piconero);
        self.counters.total_sponsor_piconero_modeled = self
            .counters
            .total_sponsor_piconero_modeled
            .saturating_add(modeled_sponsor_fee_piconero);
        self.sponsored_batches.insert(batch_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn quarantine_anomaly(
        &mut self,
        request: AnomalyQuarantineRequest,
    ) -> Result<AnomalyQuarantineRecord> {
        require(
            self.windows.contains_key(&request.window_id),
            "unknown audit window",
        )?;
        if let Some(transcript_id) = &request.transcript_id {
            require(
                self.transcripts.contains_key(transcript_id),
                "unknown transcript",
            )?;
        }
        let sequence = self.counters.next();
        let anomaly_id = anomaly_id(sequence, &request);
        require_unique(&mut self.nullifiers, "anomaly", &anomaly_id)?;
        let quarantines_window = request.severity.quarantines();
        let record = AnomalyQuarantineRecord {
            anomaly_id: anomaly_id.clone(),
            window_id: request.window_id.clone(),
            transcript_id: request.transcript_id.clone(),
            sequence,
            reporter_id: request.reporter_id,
            kind: request.kind,
            severity: request.severity,
            evidence_root: request.evidence_root,
            mitigation_root: request.mitigation_root,
            quarantines_window,
            l2_height: request.l2_height,
            expires_at_l2_height: request
                .l2_height
                .saturating_add(self.config.quarantine_ttl_blocks),
            quarantine_nonce: request.quarantine_nonce,
        };
        if let Some(transcript_id) = &request.transcript_id {
            if let Some(transcript) = self.transcripts.get_mut(transcript_id) {
                transcript.status = TranscriptStatus::Quarantined;
            }
        }
        if quarantines_window {
            if let Some(window) = self.windows.get_mut(&request.window_id) {
                window.status = AuditWindowStatus::Quarantined;
            }
            self.counters.quarantined_windows = self.counters.quarantined_windows.saturating_add(1);
        }
        self.counters.anomalies = self.counters.anomalies.saturating_add(1);
        self.anomalies.insert(anomaly_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn summarize_for_operator(
        &mut self,
        request: OperatorSummaryRequest,
    ) -> Result<OperatorSummaryRecord> {
        let window = self
            .windows
            .get(&request.window_id)
            .ok_or_else(|| format!("unknown audit window {}", request.window_id))?;
        let anomaly_count = self
            .anomalies
            .values()
            .filter(|record| record.window_id == request.window_id)
            .count() as u64;
        let proof_count_bucket = bucket_count(
            window.observed_proof_count,
            self.config.operator_summary_bucket_size,
        );
        let output_count_bucket = bucket_count(
            window.observed_output_count,
            self.config.operator_summary_bucket_size,
        );
        let sequence = self.counters.next();
        let operator_safe_summary_root = operator_safe_summary_root(
            sequence,
            &request,
            proof_count_bucket,
            output_count_bucket,
            anomaly_count,
        );
        let summary_id = summary_id(sequence, &request, &operator_safe_summary_root);
        require_unique(&mut self.nullifiers, "operator-summary", &summary_id)?;
        let record = OperatorSummaryRecord {
            summary_id: summary_id.clone(),
            window_id: request.window_id.clone(),
            sequence,
            producer_id: request.producer_id,
            audience: request.audience,
            bucketed_metrics_root: request.bucketed_metrics_root,
            redacted_exception_root: request.redacted_exception_root,
            fee_summary_root: request.fee_summary_root,
            privacy_floor_summary_root: request.privacy_floor_summary_root,
            operator_safe_summary_root,
            proof_count_bucket,
            output_count_bucket,
            anomaly_count,
            summary_nonce: request.summary_nonce,
        };
        if let Some(window) = self.windows.get_mut(&request.window_id) {
            window.latest_summary_root = record.operator_safe_summary_root.clone();
        }
        self.counters.summaries = self.counters.summaries.saturating_add(1);
        self.operator_summaries.insert(summary_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn refresh_roots(&mut self) {
        self.roots.window_root = map_root("BPP-AUDIT-WINDOW", &self.windows);
        self.roots.transcript_root = map_root("BPP-AUDIT-TRANSCRIPT", &self.transcripts);
        self.roots.attestation_root = map_root("BPP-AUDIT-ATTESTATION", &self.attestations);
        self.roots.redaction_root = map_root("BPP-AUDIT-REDACTION", &self.redactions);
        self.roots.privacy_floor_root = map_root("BPP-AUDIT-PRIVACY-FLOOR", &self.privacy_floors);
        self.roots.sponsored_batch_root =
            map_root("BPP-AUDIT-SPONSORED-BATCH", &self.sponsored_batches);
        self.roots.anomaly_root = map_root("BPP-AUDIT-ANOMALY", &self.anomalies);
        self.roots.operator_summary_root =
            map_root("BPP-AUDIT-OPERATOR-SUMMARY", &self.operator_summaries);
        self.roots.nullifier_root = set_root("BPP-AUDIT-NULLIFIER", &self.nullifiers);
        self.roots.public_record_root = domain_hash(
            "BPP-AUDIT-PUBLIC-RECORD",
            &[HashPart::Json(&self.public_record())],
            32,
        );
        self.roots.state_root = self.compute_state_root();
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": record_value(&self.config),
            "counters": record_value(&self.counters),
            "roots": record_value(&self.roots),
            "privacy_boundary": PRIVACY_BOUNDARY,
        })
    }

    pub fn state_root(&self) -> String {
        self.compute_state_root()
    }

    fn compute_state_root(&self) -> String {
        let config_record = record_value(&self.config);
        let counters_record = record_value(&self.counters);
        domain_hash(
            "BPP-AUDIT-STATE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&config_record),
                HashPart::Json(&counters_record),
                HashPart::Str(&self.roots.window_root),
                HashPart::Str(&self.roots.transcript_root),
                HashPart::Str(&self.roots.attestation_root),
                HashPart::Str(&self.roots.redaction_root),
                HashPart::Str(&self.roots.privacy_floor_root),
                HashPart::Str(&self.roots.sponsored_batch_root),
                HashPart::Str(&self.roots.anomaly_root),
                HashPart::Str(&self.roots.operator_summary_root),
                HashPart::Str(&self.roots.nullifier_root),
            ],
            32,
        )
    }

    fn recompute_window_observed_counts(&mut self, window_id: &str) {
        let mut proof_count = 0_u64;
        let mut output_count = 0_u64;
        for transcript in self.transcripts.values() {
            if transcript.window_id == window_id {
                proof_count = proof_count.saturating_add(transcript.proof_count);
                output_count = output_count.saturating_add(transcript.output_count);
            }
        }
        if let Some(window) = self.windows.get_mut(window_id) {
            window.observed_proof_count = proof_count;
            window.observed_output_count = output_count;
        }
    }

    fn window_attestation_weight_bps(&self, window_id: &str) -> u64 {
        self.attestations
            .values()
            .filter(|record| record.window_id == window_id && record.status.counts_for_quorum())
            .map(|record| record.auditor_weight_bps)
            .fold(0_u64, u64::saturating_add)
            .min(MAX_BPS)
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = State::devnet();
    state
        .open_audit_window(AuditWindowRequest {
            coordinator_id: "devnet-bpp-coordinator-0".to_string(),
            monero_height_start: DEVNET_HEIGHT,
            monero_height_end: DEVNET_HEIGHT + 48,
            l2_height_opened: 42_000,
            transcript_intake_root: seeded_root("transcript-intake"),
            range_proof_manifest_root: seeded_root("range-proof-manifest"),
            output_commitment_root: seeded_root("output-commitments"),
            ring_member_bucket_root: seeded_root("ring-member-buckets"),
            decoy_age_bucket_root: seeded_root("decoy-age-buckets"),
            expected_proof_count: 128,
            expected_output_count: 256,
            max_user_fee_bps: 4,
            operator_hint_root: seeded_root("operator-hints"),
            window_nonce: "devnet-window-0".to_string(),
        })
        .expect("demo window opens");
    state
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_unique(nullifiers: &mut BTreeSet<String>, label: &str, value: &str) -> Result<()> {
    let nullifier = domain_hash(
        "BPP-AUDIT-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    );
    if nullifiers.insert(nullifier) {
        Ok(())
    } else {
        Err(format!("duplicate {label} nullifier"))
    }
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn seeded_root(label: &str) -> String {
    domain_hash(
        "BPP-AUDIT-DEVNET-SEED",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

fn bucket_count(value: u64, bucket_size: u64) -> u64 {
    if bucket_size == 0 {
        value
    } else {
        value.div_ceil(bucket_size).saturating_mul(bucket_size)
    }
}

fn ratio_bps(observed: u64, required: u64) -> u64 {
    if required == 0 {
        MAX_BPS
    } else {
        observed.saturating_mul(MAX_BPS) / required
    }
}

fn map_root<T>(domain: &str, records: &BTreeMap<String, T>) -> String
where
    T: Serialize,
{
    let leaves = records.values().map(record_value).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, records: &BTreeSet<String>) -> String {
    let leaves = records
        .iter()
        .map(|record| json!(record))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn scoped_records_root(
    domain: &str,
    records: &BTreeMap<String, TranscriptRecord>,
    window_id: &str,
) -> String {
    let leaves = records
        .values()
        .filter(|record| record.window_id == window_id)
        .map(record_value)
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn scoped_privacy_floor_root(
    domain: &str,
    records: &BTreeMap<String, PrivacyFloorRecord>,
    window_id: &str,
) -> String {
    let leaves = records
        .values()
        .filter(|record| record.window_id == window_id)
        .map(record_value)
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn scoped_attestation_root(
    domain: &str,
    records: &BTreeMap<String, PqAttestationRecord>,
    window_id: &str,
) -> String {
    let leaves = records
        .values()
        .filter(|record| record.window_id == window_id)
        .map(record_value)
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn record_value<T: Serialize>(record: &T) -> Value {
    serde_json::to_value(record).expect("record serializes")
}

fn window_id(sequence: u64, request: &AuditWindowRequest) -> String {
    domain_hash(
        "BPP-AUDIT-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.coordinator_id),
            HashPart::U64(request.monero_height_start),
            HashPart::U64(request.monero_height_end),
            HashPart::Str(&request.transcript_intake_root),
            HashPart::Str(&request.range_proof_manifest_root),
            HashPart::Str(&request.window_nonce),
        ],
        32,
    )
}

fn transcript_id(sequence: u64, request: &TranscriptIngestRequest) -> String {
    domain_hash(
        "BPP-AUDIT-TRANSCRIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.window_id),
            HashPart::Str(&request.submitter_id),
            HashPart::Str(&request.transcript_shard_root),
            HashPart::Str(&request.range_proof_transcript_root),
            HashPart::U64(request.proof_count),
            HashPart::Str(&request.transcript_nonce),
        ],
        32,
    )
}

fn redaction_operator_safe_root(sequence: u64, request: &ViewKeyRedactionRequest) -> String {
    domain_hash(
        "BPP-AUDIT-VIEWKEY-OPERATOR-SAFE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.window_id),
            HashPart::Str(&request.transcript_id),
            HashPart::Str(&request.redacted_view_tag_root),
            HashPart::Str(&request.redacted_output_hint_root),
            HashPart::Str(&request.redacted_key_image_hint_root),
            HashPart::Str(&request.disclosure_policy_root),
        ],
        32,
    )
}

fn redaction_id(
    sequence: u64,
    request: &ViewKeyRedactionRequest,
    operator_safe_root: &str,
) -> String {
    domain_hash(
        "BPP-AUDIT-VIEWKEY-REDACTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.window_id),
            HashPart::Str(&request.transcript_id),
            HashPart::Str(&request.redactor_id),
            HashPart::Str(operator_safe_root),
            HashPart::Str(&request.redaction_nonce),
        ],
        32,
    )
}

fn privacy_floor_id(
    sequence: u64,
    request: &PrivacyFloorRequest,
    status: PrivacyFloorStatus,
    score_bps: u64,
) -> String {
    let status_tag = enum_tag(status);
    domain_hash(
        "BPP-AUDIT-PRIVACY-FLOOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.window_id),
            HashPart::Str(&request.transcript_id),
            HashPart::Str(&status_tag),
            HashPart::U64(score_bps),
            HashPart::Str(&request.ring_member_bucket_root),
            HashPart::Str(&request.decoy_distribution_root),
            HashPart::Str(&request.floor_nonce),
        ],
        32,
    )
}

fn attestation_id(sequence: u64, request: &PqAttestationRequest) -> String {
    domain_hash(
        "BPP-AUDIT-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.window_id),
            HashPart::Str(&request.auditor_id),
            HashPart::Str(&request.committee_id),
            HashPart::U64(request.l2_height),
            HashPart::U64(request.auditor_weight_bps),
            HashPart::U64(request.pq_security_bits as u64),
            HashPart::Str(&request.transcript_root),
            HashPart::Str(&request.privacy_floor_root),
            HashPart::Str(&request.attestation_nonce),
        ],
        32,
    )
}

fn sponsored_batch_id(
    sequence: u64,
    request: &SponsoredBatchRequest,
    transcript_root: &str,
) -> String {
    domain_hash(
        "BPP-AUDIT-SPONSORED-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.window_id),
            HashPart::Str(&request.sponsor_id),
            HashPart::Str(transcript_root),
            HashPart::Str(&request.settlement_root),
            HashPart::Str(&request.sponsor_signature_root),
            HashPart::Str(&request.batch_nonce),
        ],
        32,
    )
}

fn anomaly_id(sequence: u64, request: &AnomalyQuarantineRequest) -> String {
    let kind_tag = enum_tag(request.kind);
    let severity_tag = enum_tag(request.severity);
    domain_hash(
        "BPP-AUDIT-ANOMALY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.window_id),
            HashPart::Str(request.transcript_id.as_deref().unwrap_or("")),
            HashPart::Str(&request.reporter_id),
            HashPart::Str(&kind_tag),
            HashPart::Str(&severity_tag),
            HashPart::Str(&request.evidence_root),
            HashPart::Str(&request.quarantine_nonce),
        ],
        32,
    )
}

fn operator_safe_summary_root(
    sequence: u64,
    request: &OperatorSummaryRequest,
    proof_count_bucket: u64,
    output_count_bucket: u64,
    anomaly_count: u64,
) -> String {
    let audience_tag = enum_tag(request.audience);
    domain_hash(
        "BPP-AUDIT-OPERATOR-SAFE-SUMMARY-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.window_id),
            HashPart::Str(&audience_tag),
            HashPart::Str(&request.bucketed_metrics_root),
            HashPart::Str(&request.redacted_exception_root),
            HashPart::Str(&request.fee_summary_root),
            HashPart::Str(&request.privacy_floor_summary_root),
            HashPart::U64(proof_count_bucket),
            HashPart::U64(output_count_bucket),
            HashPart::U64(anomaly_count),
        ],
        32,
    )
}

fn summary_id(sequence: u64, request: &OperatorSummaryRequest, operator_safe_root: &str) -> String {
    let audience_tag = enum_tag(request.audience);
    domain_hash(
        "BPP-AUDIT-OPERATOR-SUMMARY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.window_id),
            HashPart::Str(&request.producer_id),
            HashPart::Str(&audience_tag),
            HashPart::Str(operator_safe_root),
            HashPart::Str(&request.summary_nonce),
        ],
        32,
    )
}

fn enum_tag<T: Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}
