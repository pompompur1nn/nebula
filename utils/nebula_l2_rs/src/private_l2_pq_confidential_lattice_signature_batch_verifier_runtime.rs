use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub type PrivateL2PqConfidentialLatticeSignatureBatchVerifierRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_LATTICE_SIGNATURE_BATCH_VERIFIER_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-lattice-signature-batch-verifier-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_LATTICE_SIGNATURE_BATCH_VERIFIER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "stable-fnv1a64-domain-separated-canonical-json-demo-v1";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-pq-lattice-batch-verifier-public-record-v1";
pub const PROFILE_COMMITMENT_SUITE: &str = "abstract-ml-dsa-falcon-sphincs-profile-commitment-v1";
pub const ATTESTATION_SUITE: &str = "pq-lattice-quorum-attestation-root-v1";
pub const QUARANTINE_SUITE: &str = "deterministic-failure-quarantine-root-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "private-l2-low-fee-batch-verification-rebate-hint-root-v1";
pub const PRIVACY_REDACTION_SUITE: &str = "budgeted-redaction-root-with-lane-safety-v1";
pub const DEVNET_HEIGHT: u64 = 1_312_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 2_048;
pub const DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 4;
pub const DEFAULT_QUARANTINE_BLOCKS: u64 = 720;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 1_000_000;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 14;
pub const DEFAULT_MIN_PRIVACY_SET: u64 = 65_536;
pub const DEFAULT_BASE_VERIFY_FEE_MICRONERO: u64 = 320;
pub const DEFAULT_MAX_VERIFY_FEE_MICRONERO: u64 = 8_000;
pub const MAX_VERIFIERS: usize = 524_288;
pub const MAX_PROFILES: usize = 1_048_576;
pub const MAX_BATCHES: usize = 2_097_152;
pub const MAX_ATTESTATIONS: usize = 4_194_304;
pub const MAX_FAILURES: usize = 2_097_152;
pub const MAX_REBATES: usize = 2_097_152;
pub const MAX_PRIVACY_BUDGETS: usize = 1_048_576;
pub const MAX_EVENTS: usize = 4_194_304;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationLane {
    Operator,
    Developer,
    Contract,
}
impl VerificationLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Developer => "developer",
            Self::Contract => "contract",
        }
    }
    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Operator => 1000,
            Self::Contract => 860,
            Self::Developer => 740,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LatticeSignatureFamily {
    MlDsa,
    Falcon,
    SphincsLike,
    HybridFence,
}
impl LatticeSignatureFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa => "ml_dsa",
            Self::Falcon => "falcon",
            Self::SphincsLike => "sphincs_like",
            Self::HybridFence => "hybrid_fence",
        }
    }
    pub fn expected_security_bits(self) -> u16 {
        match self {
            Self::MlDsa | Self::Falcon | Self::SphincsLike => 256,
            Self::HybridFence => 192,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierStatus {
    Candidate,
    Active,
    Saturated,
    CoolingDown,
    Quarantined,
    Retired,
}
impl VerifierStatus {
    pub fn accepts_batches(self) -> bool {
        matches!(self, Self::Active | Self::Saturated | Self::CoolingDown)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Submitted,
    ProfileMatched,
    Verifying,
    QuorumAttested,
    Settled,
    Rebated,
    Disputed,
    Quarantined,
    Rejected,
}
impl BatchStatus {
    pub fn final_status(self) -> bool {
        matches!(self, Self::Settled | Self::Rebated | Self::Rejected)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVote {
    Valid,
    Invalid,
    Abstain,
    Timeout,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    BadProfileCommitment,
    SignatureMismatch,
    QuorumRegression,
    PrivacyBudgetExceeded,
    ReplayFenceHit,
    FeeSponsorshipMismatch,
    OperatorOverride,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    VerifierRegistered,
    ProfileCommitted,
    BatchSubmitted,
    BatchMatched,
    QuorumAttested,
    FailureQuarantined,
    RebateHintIssued,
    PrivacyBudgetReserved,
    RuntimeRootPublished,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub monero_network: String,
    pub l2_network: String,
    pub activation_height: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub max_batch_items: usize,
    pub batch_window_blocks: u64,
    pub quarantine_blocks: u64,
    pub privacy_redaction_budget_units: u64,
    pub low_fee_rebate_bps: u64,
    pub min_privacy_set: u64,
    pub base_verify_fee_micronero: u64,
    pub max_verify_fee_micronero: u64,
    pub allowed_lanes: BTreeSet<VerificationLane>,
    pub allowed_families: BTreeSet<LatticeSignatureFamily>,
    pub require_quorum_attestation: bool,
    pub require_redacted_public_records: bool,
    pub allow_low_fee_rebate_hints: bool,
    pub quarantine_on_privacy_exhaustion: bool,
}
impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            monero_network: "monero-devnet".to_string(),
            l2_network: "nebula-private-l2-devnet".to_string(),
            activation_height: DEVNET_HEIGHT,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            quorum_bps: DEFAULT_QUORUM_BPS,
            strong_quorum_bps: DEFAULT_STRONG_QUORUM_BPS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
            batch_window_blocks: DEFAULT_BATCH_WINDOW_BLOCKS,
            quarantine_blocks: DEFAULT_QUARANTINE_BLOCKS,
            privacy_redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            min_privacy_set: DEFAULT_MIN_PRIVACY_SET,
            base_verify_fee_micronero: DEFAULT_BASE_VERIFY_FEE_MICRONERO,
            max_verify_fee_micronero: DEFAULT_MAX_VERIFY_FEE_MICRONERO,
            allowed_lanes: BTreeSet::from([
                VerificationLane::Operator,
                VerificationLane::Developer,
                VerificationLane::Contract,
            ]),
            allowed_families: BTreeSet::from([
                LatticeSignatureFamily::MlDsa,
                LatticeSignatureFamily::Falcon,
                LatticeSignatureFamily::SphincsLike,
            ]),
            require_quorum_attestation: true,
            require_redacted_public_records: true,
            allow_low_fee_rebate_hints: true,
            quarantine_on_privacy_exhaustion: true,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({ "protocol_version": self.protocol_version, "schema_version": SCHEMA_VERSION, "hash_suite": HASH_SUITE, "public_record_suite": PUBLIC_RECORD_SUITE, "profile_commitment_suite": PROFILE_COMMITMENT_SUITE, "attestation_suite": ATTESTATION_SUITE, "quarantine_suite": QUARANTINE_SUITE, "low_fee_rebate_suite": LOW_FEE_REBATE_SUITE, "privacy_redaction_suite": PRIVACY_REDACTION_SUITE, "monero_network": self.monero_network, "l2_network": self.l2_network, "activation_height": self.activation_height, "min_pq_security_bits": self.min_pq_security_bits, "target_pq_security_bits": self.target_pq_security_bits, "quorum_bps": self.quorum_bps, "strong_quorum_bps": self.strong_quorum_bps, "max_batch_items": self.max_batch_items, "batch_window_blocks": self.batch_window_blocks, "quarantine_blocks": self.quarantine_blocks, "privacy_redaction_budget_units": self.privacy_redaction_budget_units, "low_fee_rebate_bps": self.low_fee_rebate_bps, "min_privacy_set": self.min_privacy_set, "base_verify_fee_micronero": self.base_verify_fee_micronero, "max_verify_fee_micronero": self.max_verify_fee_micronero, "allowed_lanes": self.allowed_lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(), "allowed_families": self.allowed_families.iter().map(|family| family.as_str()).collect::<Vec<_>>(), "require_quorum_attestation": self.require_quorum_attestation, "require_redacted_public_records": self.require_redacted_public_records, "allow_low_fee_rebate_hints": self.allow_low_fee_rebate_hints, "quarantine_on_privacy_exhaustion": self.quarantine_on_privacy_exhaustion })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub verifier_count: u64,
    pub profile_count: u64,
    pub batch_count: u64,
    pub attestation_count: u64,
    pub quarantine_count: u64,
    pub rebate_hint_count: u64,
    pub privacy_budget_count: u64,
    pub event_count: u64,
    pub settled_batches: u64,
    pub rejected_batches: u64,
    pub total_items_submitted: u64,
    pub total_items_verified: u64,
    pub total_fee_micronero: u64,
    pub total_rebate_hint_micronero: u64,
    pub total_redaction_units_reserved: u64,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub verifier_registry_root: String,
    pub profile_commitment_root: String,
    pub batch_submission_root: String,
    pub quorum_attestation_root: String,
    pub failure_quarantine_root: String,
    pub low_fee_rebate_hint_root: String,
    pub privacy_redaction_budget_root: String,
    pub event_root: String,
    pub public_record_root: String,
    pub state_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatticeProfileMetadata {
    pub profile_id: String,
    pub family: LatticeSignatureFamily,
    pub parameter_set: String,
    pub abstract_public_key_commitment: String,
    pub abstract_signature_commitment: String,
    pub transcript_domain: String,
    pub security_bits: u16,
    pub estimated_verify_weight: u64,
    pub max_signature_bytes: u64,
    pub aggregation_hint: String,
    pub side_channel_notes_commitment: String,
    pub active_from_height: u64,
    pub retired_at_height: Option<u64>,
}
impl LatticeProfileMetadata {
    pub fn public_record(&self) -> Value {
        json!({ "profile_id": self.profile_id, "family": self.family.as_str(), "parameter_set": self.parameter_set, "profile_commitment": stable_id("profile", &stable_json(&json!(self))), "security_bits": self.security_bits, "estimated_verify_weight": self.estimated_verify_weight, "max_signature_bytes": self.max_signature_bytes, "aggregation_hint": self.aggregation_hint, "active_from_height": self.active_from_height, "retired_at_height": self.retired_at_height })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifierRegistryEntry {
    pub verifier_id: String,
    pub operator_commitment: String,
    pub lane_authorizations: BTreeSet<VerificationLane>,
    pub supported_profiles: BTreeSet<String>,
    pub status: VerifierStatus,
    pub stake_commitment: String,
    pub endpoint_commitment: String,
    pub locality_hint: String,
    pub max_parallel_batches: u64,
    pub low_fee_score: u64,
    pub privacy_score: u64,
    pub registered_height: u64,
    pub last_heartbeat_height: u64,
}
impl VerifierRegistryEntry {
    pub fn accepts_lane(&self, lane: VerificationLane) -> bool {
        self.status.accepts_batches() && self.lane_authorizations.contains(&lane)
    }
    pub fn public_record(&self) -> Value {
        json!({ "verifier_id": self.verifier_id, "operator_commitment": self.operator_commitment, "lane_authorizations": self.lane_authorizations.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(), "supported_profiles": self.supported_profiles.iter().cloned().collect::<Vec<_>>(), "status": format!("{:?}", self.status).to_ascii_lowercase(), "stake_commitment": self.stake_commitment, "endpoint_commitment": self.endpoint_commitment, "locality_hint": self.locality_hint, "max_parallel_batches": self.max_parallel_batches, "low_fee_score": self.low_fee_score, "privacy_score": self.privacy_score, "registered_height": self.registered_height, "last_heartbeat_height": self.last_heartbeat_height })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BatchSubmission {
    pub batch_id: String,
    pub lane: VerificationLane,
    pub submitter_commitment: String,
    pub profile_id: String,
    pub message_set_commitment: String,
    pub signature_set_commitment: String,
    pub nullifier_fence_root: String,
    pub item_count: u64,
    pub privacy_set_size: u64,
    pub redaction_budget_id: String,
    pub fee_paid_micronero: u64,
    pub low_fee_rebate_hint_id: Option<String>,
    pub assigned_verifiers: BTreeSet<String>,
    pub status: BatchStatus,
    pub submitted_height: u64,
    pub deadline_height: u64,
}
impl BatchSubmission {
    pub fn public_record(&self) -> Value {
        json!({ "batch_id": self.batch_id, "lane": self.lane.as_str(), "submitter_commitment": self.submitter_commitment, "profile_id": self.profile_id, "message_set_commitment": self.message_set_commitment, "signature_set_commitment": self.signature_set_commitment, "nullifier_fence_root": self.nullifier_fence_root, "item_count": self.item_count, "privacy_set_size": self.privacy_set_size, "redaction_budget_id": self.redaction_budget_id, "fee_paid_micronero": self.fee_paid_micronero, "low_fee_rebate_hint_id": self.low_fee_rebate_hint_id, "assigned_verifiers": self.assigned_verifiers.iter().cloned().collect::<Vec<_>>(), "status": format!("{:?}", self.status).to_ascii_lowercase(), "submitted_height": self.submitted_height, "deadline_height": self.deadline_height })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QuorumAttestation {
    pub attestation_id: String,
    pub batch_id: String,
    pub verifier_id: String,
    pub vote: AttestationVote,
    pub attested_item_count: u64,
    pub failure_count: u64,
    pub transcript_root: String,
    pub redacted_diagnostics_root: String,
    pub pq_attestation_commitment: String,
    pub weight_bps: u64,
    pub attested_height: u64,
}
impl QuorumAttestation {
    pub fn public_record(&self) -> Value {
        json!({ "attestation_id": self.attestation_id, "batch_id": self.batch_id, "verifier_id": self.verifier_id, "vote": format!("{:?}", self.vote).to_ascii_lowercase(), "attested_item_count": self.attested_item_count, "failure_count": self.failure_count, "transcript_root": self.transcript_root, "redacted_diagnostics_root": self.redacted_diagnostics_root, "pq_attestation_commitment": self.pq_attestation_commitment, "weight_bps": self.weight_bps, "attested_height": self.attested_height })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FailureQuarantine {
    pub quarantine_id: String,
    pub batch_id: String,
    pub profile_id: String,
    pub lane: VerificationLane,
    pub reason: QuarantineReason,
    pub evidence_commitment: String,
    pub affected_item_count: u64,
    pub opened_height: u64,
    pub release_height: u64,
    pub operator_review_commitment: String,
}
impl FailureQuarantine {
    pub fn public_record(&self) -> Value {
        json!({ "quarantine_id": self.quarantine_id, "batch_id": self.batch_id, "profile_id": self.profile_id, "lane": self.lane.as_str(), "reason": format!("{:?}", self.reason).to_ascii_lowercase(), "evidence_commitment": self.evidence_commitment, "affected_item_count": self.affected_item_count, "opened_height": self.opened_height, "release_height": self.release_height, "operator_review_commitment": self.operator_review_commitment })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeRebateHint {
    pub rebate_hint_id: String,
    pub batch_id: String,
    pub lane: VerificationLane,
    pub sponsor_commitment: String,
    pub estimated_rebate_micronero: u64,
    pub rebate_bps: u64,
    pub reason_code: String,
    pub claim_window_start: u64,
    pub claim_window_end: u64,
}
impl LowFeeRebateHint {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub lane: VerificationLane,
    pub owner_commitment: String,
    pub allowed_public_fields: BTreeSet<String>,
    pub redacted_field_commitment_root: String,
    pub budget_units: u64,
    pub consumed_units: u64,
    pub min_privacy_set: u64,
    pub renewal_height: u64,
}
impl PrivacyRedactionBudget {
    pub fn available_units(&self) -> u64 {
        self.budget_units.saturating_sub(self.consumed_units)
    }
    pub fn public_record(&self) -> Value {
        json!({ "budget_id": self.budget_id, "lane": self.lane.as_str(), "owner_commitment": self.owner_commitment, "allowed_public_fields": self.allowed_public_fields.iter().cloned().collect::<Vec<_>>(), "redacted_field_commitment_root": self.redacted_field_commitment_root, "budget_units": self.budget_units, "consumed_units": self.consumed_units, "available_units": self.available_units(), "min_privacy_set": self.min_privacy_set, "renewal_height": self.renewal_height })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub kind: EventKind,
    pub lane: Option<VerificationLane>,
    pub subject_id: String,
    pub public_commitment: String,
    pub height: u64,
}
impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({ "event_id": self.event_id, "kind": format!("{:?}", self.kind).to_ascii_lowercase(), "lane": self.lane.map(|lane| lane.as_str()), "subject_id": self.subject_id, "public_commitment": self.public_commitment, "height": self.height })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_height: u64,
    pub verifiers: BTreeMap<String, VerifierRegistryEntry>,
    pub profiles: BTreeMap<String, LatticeProfileMetadata>,
    pub batches: BTreeMap<String, BatchSubmission>,
    pub attestations: BTreeMap<String, QuorumAttestation>,
    pub quarantines: BTreeMap<String, FailureQuarantine>,
    pub rebate_hints: BTreeMap<String, LowFeeRebateHint>,
    pub privacy_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub events: BTreeMap<String, RuntimeEvent>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::devnet(), DEVNET_HEIGHT)
    }
}
impl State {
    pub fn new(config: Config, current_height: u64) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            current_height,
            verifiers: BTreeMap::new(),
            profiles: BTreeMap::new(),
            batches: BTreeMap::new(),
            attestations: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            rebate_hints: BTreeMap::new(),
            privacy_budgets: BTreeMap::new(),
            events: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }
    pub fn register_verifier(
        &mut self,
        operator_commitment: impl Into<String>,
        lane_authorizations: BTreeSet<VerificationLane>,
        supported_profiles: BTreeSet<String>,
        stake_commitment: impl Into<String>,
        endpoint_commitment: impl Into<String>,
        locality_hint: impl Into<String>,
    ) -> PrivateL2PqConfidentialLatticeSignatureBatchVerifierRuntimeResult<String> {
        if self.verifiers.len() >= MAX_VERIFIERS {
            return Err("verifier registry capacity exceeded".to_string());
        }
        if !lane_authorizations
            .iter()
            .all(|lane| self.config.allowed_lanes.contains(lane))
        {
            return Err("verifier requested a lane disabled by config".to_string());
        }
        let operator_commitment = operator_commitment.into();
        let verifier_id = stable_id(
            "verifier",
            &stable_json(
                &json!({"operator_commitment": operator_commitment, "height": self.current_height, "index": self.verifiers.len()}),
            ),
        );
        let entry = VerifierRegistryEntry {
            verifier_id: verifier_id.clone(),
            operator_commitment,
            lane_authorizations,
            supported_profiles,
            status: VerifierStatus::Active,
            stake_commitment: stake_commitment.into(),
            endpoint_commitment: endpoint_commitment.into(),
            locality_hint: locality_hint.into(),
            max_parallel_batches: 32,
            low_fee_score: 920,
            privacy_score: 960,
            registered_height: self.current_height,
            last_heartbeat_height: self.current_height,
        };
        self.verifiers.insert(verifier_id.clone(), entry);
        self.counters.verifier_count = self.verifiers.len() as u64;
        self.push_event(EventKind::VerifierRegistered, None, verifier_id.clone());
        self.refresh_roots();
        Ok(verifier_id)
    }
    pub fn commit_profile(
        &mut self,
        family: LatticeSignatureFamily,
        parameter_set: impl Into<String>,
        public_key_commitment: impl Into<String>,
        signature_commitment: impl Into<String>,
        transcript_domain: impl Into<String>,
    ) -> PrivateL2PqConfidentialLatticeSignatureBatchVerifierRuntimeResult<String> {
        if self.profiles.len() >= MAX_PROFILES {
            return Err("profile registry capacity exceeded".to_string());
        }
        if !self.config.allowed_families.contains(&family) {
            return Err("signature family disabled by config".to_string());
        }
        if family.expected_security_bits() < self.config.min_pq_security_bits {
            return Err("signature family below minimum pq security bits".to_string());
        }
        let parameter_set = parameter_set.into();
        let abstract_public_key_commitment = public_key_commitment.into();
        let abstract_signature_commitment = signature_commitment.into();
        let transcript_domain = transcript_domain.into();
        let profile_id = stable_id(
            "profile",
            &stable_json(
                &json!({"family": family.as_str(), "parameter_set": parameter_set, "public_key_commitment": abstract_public_key_commitment, "signature_commitment": abstract_signature_commitment, "transcript_domain": transcript_domain}),
            ),
        );
        let profile = LatticeProfileMetadata {
            profile_id: profile_id.clone(),
            family,
            parameter_set,
            abstract_public_key_commitment,
            abstract_signature_commitment,
            transcript_domain,
            security_bits: family.expected_security_bits(),
            estimated_verify_weight: match family {
                LatticeSignatureFamily::MlDsa => 8,
                LatticeSignatureFamily::Falcon => 11,
                LatticeSignatureFamily::SphincsLike => 38,
                LatticeSignatureFamily::HybridFence => 44,
            },
            max_signature_bytes: match family {
                LatticeSignatureFamily::MlDsa => 4595,
                LatticeSignatureFamily::Falcon => 1330,
                LatticeSignatureFamily::SphincsLike => 49856,
                LatticeSignatureFamily::HybridFence => 64000,
            },
            aggregation_hint: "abstract_batch_verify_only_no_raw_keys".to_string(),
            side_channel_notes_commitment: stable_id("side_channel_notes", family.as_str()),
            active_from_height: self.current_height,
            retired_at_height: None,
        };
        self.profiles.insert(profile_id.clone(), profile);
        self.counters.profile_count = self.profiles.len() as u64;
        self.push_event(EventKind::ProfileCommitted, None, profile_id.clone());
        self.refresh_roots();
        Ok(profile_id)
    }
    pub fn reserve_privacy_budget(
        &mut self,
        lane: VerificationLane,
        owner_commitment: impl Into<String>,
        budget_units: u64,
        allowed_public_fields: BTreeSet<String>,
    ) -> PrivateL2PqConfidentialLatticeSignatureBatchVerifierRuntimeResult<String> {
        if self.privacy_budgets.len() >= MAX_PRIVACY_BUDGETS {
            return Err("privacy budget capacity exceeded".to_string());
        }
        if !self.config.allowed_lanes.contains(&lane) {
            return Err("privacy budget lane disabled by config".to_string());
        }
        let owner_commitment = owner_commitment.into();
        let budget_id = stable_id(
            "privacy_budget",
            &stable_json(
                &json!({"lane": lane.as_str(), "owner_commitment": owner_commitment, "height": self.current_height, "index": self.privacy_budgets.len()}),
            ),
        );
        let redacted_field_commitment_root = root_from_values(
            "redacted_fields",
            allowed_public_fields
                .iter()
                .map(|field| json!(field))
                .collect(),
        );
        let budget = PrivacyRedactionBudget {
            budget_id: budget_id.clone(),
            lane,
            owner_commitment,
            allowed_public_fields,
            redacted_field_commitment_root,
            budget_units,
            consumed_units: 0,
            min_privacy_set: self.config.min_privacy_set,
            renewal_height: self.current_height + 10080,
        };
        self.privacy_budgets.insert(budget_id.clone(), budget);
        self.counters.privacy_budget_count = self.privacy_budgets.len() as u64;
        self.push_event(
            EventKind::PrivacyBudgetReserved,
            Some(lane),
            budget_id.clone(),
        );
        self.refresh_roots();
        Ok(budget_id)
    }
    pub fn submit_batch(
        &mut self,
        lane: VerificationLane,
        submitter_commitment: impl Into<String>,
        profile_id: impl Into<String>,
        message_set_commitment: impl Into<String>,
        signature_set_commitment: impl Into<String>,
        nullifier_fence_root: impl Into<String>,
        item_count: u64,
        privacy_set_size: u64,
        redaction_budget_id: impl Into<String>,
        fee_paid_micronero: u64,
    ) -> PrivateL2PqConfidentialLatticeSignatureBatchVerifierRuntimeResult<String> {
        if self.batches.len() >= MAX_BATCHES {
            return Err("batch capacity exceeded".to_string());
        }
        if !self.config.allowed_lanes.contains(&lane) {
            return Err("batch lane disabled by config".to_string());
        }
        if item_count == 0 || item_count as usize > self.config.max_batch_items {
            return Err("batch item count outside configured bounds".to_string());
        }
        if privacy_set_size < self.config.min_privacy_set {
            return Err("batch privacy set below configured minimum".to_string());
        }
        let profile_id = profile_id.into();
        if !self.profiles.contains_key(&profile_id) {
            return Err("unknown lattice signature profile".to_string());
        }
        let redaction_budget_id = redaction_budget_id.into();
        let required_units = redaction_units(lane, item_count);
        let budget = self
            .privacy_budgets
            .get_mut(&redaction_budget_id)
            .ok_or_else(|| "unknown privacy redaction budget".to_string())?;
        if budget.lane != lane {
            return Err("privacy budget lane mismatch".to_string());
        }
        if budget.available_units() < required_units && self.config.quarantine_on_privacy_exhaustion
        {
            return Err("privacy redaction budget exhausted".to_string());
        }
        budget.consumed_units = budget.consumed_units.saturating_add(required_units);
        let submitter_commitment = submitter_commitment.into();
        let message_set_commitment = message_set_commitment.into();
        let signature_set_commitment = signature_set_commitment.into();
        let nullifier_fence_root = nullifier_fence_root.into();
        let batch_id = stable_id(
            "batch",
            &stable_json(
                &json!({"lane": lane.as_str(), "submitter_commitment": submitter_commitment, "profile_id": profile_id, "message_set_commitment": message_set_commitment, "signature_set_commitment": signature_set_commitment, "nullifier_fence_root": nullifier_fence_root, "item_count": item_count, "height": self.current_height}),
            ),
        );
        let assigned_verifiers = self.pick_verifiers(lane, &profile_id, 3);
        let mut batch = BatchSubmission {
            batch_id: batch_id.clone(),
            lane,
            submitter_commitment,
            profile_id,
            message_set_commitment,
            signature_set_commitment,
            nullifier_fence_root,
            item_count,
            privacy_set_size,
            redaction_budget_id,
            fee_paid_micronero,
            low_fee_rebate_hint_id: None,
            assigned_verifiers,
            status: BatchStatus::Submitted,
            submitted_height: self.current_height,
            deadline_height: self.current_height + self.config.batch_window_blocks,
        };
        if !batch.assigned_verifiers.is_empty() {
            batch.status = BatchStatus::ProfileMatched;
            self.push_event(EventKind::BatchMatched, Some(lane), batch_id.clone());
        }
        self.counters.total_items_submitted = self
            .counters
            .total_items_submitted
            .saturating_add(item_count);
        self.counters.total_fee_micronero = self
            .counters
            .total_fee_micronero
            .saturating_add(fee_paid_micronero);
        self.counters.total_redaction_units_reserved = self
            .counters
            .total_redaction_units_reserved
            .saturating_add(required_units);
        self.batches.insert(batch_id.clone(), batch);
        self.counters.batch_count = self.batches.len() as u64;
        self.push_event(EventKind::BatchSubmitted, Some(lane), batch_id.clone());
        self.refresh_roots();
        Ok(batch_id)
    }

    pub fn attest_batch(
        &mut self,
        batch_id: impl Into<String>,
        verifier_id: impl Into<String>,
        vote: AttestationVote,
        failure_count: u64,
        transcript_root: impl Into<String>,
        redacted_diagnostics_root: impl Into<String>,
        pq_attestation_commitment: impl Into<String>,
    ) -> PrivateL2PqConfidentialLatticeSignatureBatchVerifierRuntimeResult<String> {
        if self.attestations.len() >= MAX_ATTESTATIONS {
            return Err("attestation capacity exceeded".to_string());
        }
        let batch_id = batch_id.into();
        let verifier_id = verifier_id.into();
        let batch = self
            .batches
            .get(&batch_id)
            .ok_or_else(|| "unknown batch".to_string())?;
        let verifier = self
            .verifiers
            .get(&verifier_id)
            .ok_or_else(|| "unknown verifier".to_string())?;
        if !batch.assigned_verifiers.contains(&verifier_id) {
            return Err("verifier was not assigned to batch".to_string());
        }
        if !verifier.accepts_lane(batch.lane) {
            return Err("verifier cannot attest this lane".to_string());
        }
        let transcript_root = transcript_root.into();
        let redacted_diagnostics_root = redacted_diagnostics_root.into();
        let pq_attestation_commitment = pq_attestation_commitment.into();
        let attestation_id = stable_id(
            "attestation",
            &stable_json(
                &json!({"batch_id": batch_id, "verifier_id": verifier_id, "vote": format!("{:?}", vote).to_ascii_lowercase(), "transcript_root": transcript_root, "height": self.current_height}),
            ),
        );
        let attestation = QuorumAttestation {
            attestation_id: attestation_id.clone(),
            batch_id: batch_id.clone(),
            verifier_id,
            vote,
            attested_item_count: batch.item_count.saturating_sub(failure_count),
            failure_count,
            transcript_root,
            redacted_diagnostics_root,
            pq_attestation_commitment,
            weight_bps: verifier.low_fee_score.min(MAX_BPS),
            attested_height: self.current_height,
        };
        let lane = batch.lane;
        self.attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.attestation_count = self.attestations.len() as u64;
        self.recompute_batch_status(&batch_id)?;
        self.push_event(
            EventKind::QuorumAttested,
            Some(lane),
            attestation_id.clone(),
        );
        self.refresh_roots();
        Ok(attestation_id)
    }
    pub fn quarantine_failure(
        &mut self,
        batch_id: impl Into<String>,
        reason: QuarantineReason,
        evidence_commitment: impl Into<String>,
        affected_item_count: u64,
    ) -> PrivateL2PqConfidentialLatticeSignatureBatchVerifierRuntimeResult<String> {
        if self.quarantines.len() >= MAX_FAILURES {
            return Err("failure quarantine capacity exceeded".to_string());
        }
        let batch_id = batch_id.into();
        let batch = self
            .batches
            .get_mut(&batch_id)
            .ok_or_else(|| "unknown batch".to_string())?;
        batch.status = BatchStatus::Quarantined;
        let quarantine_id = stable_id(
            "quarantine",
            &stable_json(
                &json!({"batch_id": batch_id, "reason": format!("{:?}", reason).to_ascii_lowercase(), "affected_item_count": affected_item_count, "height": self.current_height}),
            ),
        );
        let lane = batch.lane;
        let quarantine = FailureQuarantine {
            quarantine_id: quarantine_id.clone(),
            batch_id: batch_id.clone(),
            profile_id: batch.profile_id.clone(),
            lane,
            reason,
            evidence_commitment: evidence_commitment.into(),
            affected_item_count,
            opened_height: self.current_height,
            release_height: self.current_height + self.config.quarantine_blocks,
            operator_review_commitment: stable_id("operator_review", &batch_id),
        };
        self.quarantines.insert(quarantine_id.clone(), quarantine);
        self.counters.quarantine_count = self.quarantines.len() as u64;
        self.push_event(
            EventKind::FailureQuarantined,
            Some(lane),
            quarantine_id.clone(),
        );
        self.refresh_roots();
        Ok(quarantine_id)
    }
    pub fn issue_low_fee_rebate_hint(
        &mut self,
        batch_id: impl Into<String>,
        sponsor_commitment: impl Into<String>,
        reason_code: impl Into<String>,
    ) -> PrivateL2PqConfidentialLatticeSignatureBatchVerifierRuntimeResult<String> {
        if !self.config.allow_low_fee_rebate_hints {
            return Err("low fee rebate hints disabled".to_string());
        }
        if self.rebate_hints.len() >= MAX_REBATES {
            return Err("rebate hint capacity exceeded".to_string());
        }
        let batch_id = batch_id.into();
        let batch = self
            .batches
            .get_mut(&batch_id)
            .ok_or_else(|| "unknown batch".to_string())?;
        let estimated_rebate_micronero = batch
            .fee_paid_micronero
            .saturating_mul(self.config.low_fee_rebate_bps)
            / MAX_BPS;
        let rebate_hint_id = stable_id(
            "rebate_hint",
            &stable_json(
                &json!({"batch_id": batch_id, "fee_paid_micronero": batch.fee_paid_micronero, "height": self.current_height}),
            ),
        );
        let hint = LowFeeRebateHint {
            rebate_hint_id: rebate_hint_id.clone(),
            batch_id: batch_id.clone(),
            lane: batch.lane,
            sponsor_commitment: sponsor_commitment.into(),
            estimated_rebate_micronero,
            rebate_bps: self.config.low_fee_rebate_bps,
            reason_code: reason_code.into(),
            claim_window_start: self.current_height,
            claim_window_end: self.current_height + 720,
        };
        batch.low_fee_rebate_hint_id = Some(rebate_hint_id.clone());
        if batch.status == BatchStatus::Settled {
            batch.status = BatchStatus::Rebated;
        }
        let lane = batch.lane;
        self.rebate_hints.insert(rebate_hint_id.clone(), hint);
        self.counters.rebate_hint_count = self.rebate_hints.len() as u64;
        self.counters.total_rebate_hint_micronero = self
            .counters
            .total_rebate_hint_micronero
            .saturating_add(estimated_rebate_micronero);
        self.push_event(
            EventKind::RebateHintIssued,
            Some(lane),
            rebate_hint_id.clone(),
        );
        self.refresh_roots();
        Ok(rebate_hint_id)
    }
    pub fn public_record(&self) -> Value {
        json!({ "config": self.config.public_record(), "counters": self.counters.public_record(), "roots": self.roots.public_record(), "current_height": self.current_height, "verifiers": self.verifiers.values().map(VerifierRegistryEntry::public_record).collect::<Vec<_>>(), "profiles": self.profiles.values().map(LatticeProfileMetadata::public_record).collect::<Vec<_>>(), "batches": self.batches.values().map(BatchSubmission::public_record).collect::<Vec<_>>(), "attestations": self.attestations.values().map(QuorumAttestation::public_record).collect::<Vec<_>>(), "quarantines": self.quarantines.values().map(FailureQuarantine::public_record).collect::<Vec<_>>(), "rebate_hints": self.rebate_hints.values().map(LowFeeRebateHint::public_record).collect::<Vec<_>>(), "privacy_budgets": self.privacy_budgets.values().map(PrivacyRedactionBudget::public_record).collect::<Vec<_>>(), "events": self.events.values().map(RuntimeEvent::public_record).collect::<Vec<_>>() })
    }
    pub fn state_root(&self) -> String {
        stable_id("state_root", &stable_json(&self.public_record()))
    }
    pub fn refresh_roots(&mut self) {
        let verifier_registry_root = root_from_values(
            "verifier_registry",
            self.verifiers
                .values()
                .map(VerifierRegistryEntry::public_record)
                .collect(),
        );
        let profile_commitment_root = root_from_values(
            "profile_commitments",
            self.profiles
                .values()
                .map(LatticeProfileMetadata::public_record)
                .collect(),
        );
        let batch_submission_root = root_from_values(
            "batch_submissions",
            self.batches
                .values()
                .map(BatchSubmission::public_record)
                .collect(),
        );
        let quorum_attestation_root = root_from_values(
            "quorum_attestations",
            self.attestations
                .values()
                .map(QuorumAttestation::public_record)
                .collect(),
        );
        let failure_quarantine_root = root_from_values(
            "failure_quarantines",
            self.quarantines
                .values()
                .map(FailureQuarantine::public_record)
                .collect(),
        );
        let low_fee_rebate_hint_root = root_from_values(
            "low_fee_rebate_hints",
            self.rebate_hints
                .values()
                .map(LowFeeRebateHint::public_record)
                .collect(),
        );
        let privacy_redaction_budget_root = root_from_values(
            "privacy_redaction_budgets",
            self.privacy_budgets
                .values()
                .map(PrivacyRedactionBudget::public_record)
                .collect(),
        );
        let event_root = root_from_values(
            "events",
            self.events
                .values()
                .map(RuntimeEvent::public_record)
                .collect(),
        );
        let public_record_root = stable_id(
            "public_record",
            &stable_json(
                &json!({"config": self.config.public_record(), "counters": self.counters.public_record(), "verifier_registry_root": verifier_registry_root, "profile_commitment_root": profile_commitment_root, "batch_submission_root": batch_submission_root, "quorum_attestation_root": quorum_attestation_root, "failure_quarantine_root": failure_quarantine_root, "low_fee_rebate_hint_root": low_fee_rebate_hint_root, "privacy_redaction_budget_root": privacy_redaction_budget_root, "event_root": event_root, "current_height": self.current_height}),
            ),
        );
        let state_root = stable_id(
            "state",
            &stable_json(
                &json!({"public_record_root": public_record_root, "protocol_version": self.config.protocol_version, "current_height": self.current_height}),
            ),
        );
        self.roots = Roots {
            verifier_registry_root,
            profile_commitment_root,
            batch_submission_root,
            quorum_attestation_root,
            failure_quarantine_root,
            low_fee_rebate_hint_root,
            privacy_redaction_budget_root,
            event_root,
            public_record_root,
            state_root,
        };
    }
    fn pick_verifiers(
        &self,
        lane: VerificationLane,
        profile_id: &str,
        limit: usize,
    ) -> BTreeSet<String> {
        self.verifiers
            .values()
            .filter(|verifier| {
                verifier.accepts_lane(lane) && verifier.supported_profiles.contains(profile_id)
            })
            .take(limit)
            .map(|verifier| verifier.verifier_id.clone())
            .collect()
    }
    fn recompute_batch_status(
        &mut self,
        batch_id: &str,
    ) -> PrivateL2PqConfidentialLatticeSignatureBatchVerifierRuntimeResult<()> {
        let Some(batch) = self.batches.get(batch_id) else {
            return Err("unknown batch".to_string());
        };
        let valid_weight: u64 = self
            .attestations
            .values()
            .filter(|a| a.batch_id == batch_id && a.vote == AttestationVote::Valid)
            .map(|a| a.weight_bps)
            .sum();
        let invalid_weight: u64 = self
            .attestations
            .values()
            .filter(|a| a.batch_id == batch_id && a.vote == AttestationVote::Invalid)
            .map(|a| a.weight_bps)
            .sum();
        let item_count = batch.item_count;
        let lane = batch.lane;
        let next_status = if invalid_weight >= self.config.quorum_bps {
            BatchStatus::Disputed
        } else if valid_weight >= self.config.strong_quorum_bps {
            BatchStatus::Settled
        } else if valid_weight >= self.config.quorum_bps {
            BatchStatus::QuorumAttested
        } else {
            BatchStatus::Verifying
        };
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| "unknown batch".to_string())?;
        batch.status = next_status;
        if next_status == BatchStatus::Settled {
            self.counters.settled_batches = self.counters.settled_batches.saturating_add(1);
            self.counters.total_items_verified = self
                .counters
                .total_items_verified
                .saturating_add(item_count);
        }
        if next_status == BatchStatus::Disputed {
            self.counters.rejected_batches = self.counters.rejected_batches.saturating_add(1);
        }
        self.push_event(EventKind::QuorumAttested, Some(lane), batch_id.to_string());
        Ok(())
    }
    fn push_event(&mut self, kind: EventKind, lane: Option<VerificationLane>, subject_id: String) {
        if self.events.len() >= MAX_EVENTS {
            return;
        }
        let event_id = stable_id(
            "event",
            &stable_json(
                &json!({"kind": format!("{:?}", kind).to_ascii_lowercase(), "lane": lane.map(|item| item.as_str()), "subject_id": subject_id, "height": self.current_height, "index": self.events.len()}),
            ),
        );
        let event = RuntimeEvent {
            event_id: event_id.clone(),
            kind,
            lane,
            subject_id,
            public_commitment: stable_id("event_commitment", &event_id),
            height: self.current_height,
        };
        self.events.insert(event_id, event);
        self.counters.event_count = self.events.len() as u64;
    }
}

pub fn devnet() -> State {
    let mut state = State::new(Config::devnet(), DEVNET_HEIGHT);
    seed_devnet(&mut state);
    state.refresh_roots();
    state
}
pub fn demo() -> State {
    let mut state = devnet();
    state.current_height += 3;
    let operator_batch = state
        .submit_batch(
            VerificationLane::Operator,
            "operator-submitment-redacted-commitment-demo",
            "profile-ml-dsa-devnet",
            "operator-message-set-root-demo",
            "operator-signature-set-root-demo",
            "operator-nullifier-fence-root-demo",
            512,
            131072,
            "budget-operator-devnet",
            212000,
        )
        .unwrap_or_else(|_| "batch-operator-demo-unavailable".to_string());
    for verifier_id in state
        .batches
        .get(&operator_batch)
        .map(|batch| batch.assigned_verifiers.iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default()
    {
        let _ = state.attest_batch(
            operator_batch.clone(),
            verifier_id,
            AttestationVote::Valid,
            0,
            "operator-transcript-root-demo",
            "operator-redacted-diagnostics-root-demo",
            "operator-pq-attestation-commitment-demo",
        );
    }
    let _ = state.issue_low_fee_rebate_hint(
        operator_batch.clone(),
        "fee-sponsor-commitment-demo",
        "batch_density_operator_lane",
    );
    let contract_batch = state
        .submit_batch(
            VerificationLane::Contract,
            "contract-submitment-redacted-commitment-demo",
            "profile-falcon-devnet",
            "contract-message-set-root-demo",
            "contract-signature-set-root-demo",
            "contract-nullifier-fence-root-demo",
            128,
            262144,
            "budget-contract-devnet",
            144000,
        )
        .unwrap_or_else(|_| "batch-contract-demo-unavailable".to_string());
    let _ = state.quarantine_failure(
        contract_batch,
        QuarantineReason::SignatureMismatch,
        "contract-batch-redacted-failure-evidence-demo",
        2,
    );
    state.refresh_roots();
    state
}
pub fn public_record(state: &State) -> Value {
    state.public_record()
}
pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn seed_devnet(state: &mut State) {
    let profiles = [
        (
            "profile-ml-dsa-devnet",
            LatticeSignatureFamily::MlDsa,
            "ml-dsa-87-abstract",
            8,
            4595,
            "batch_verify_operator_and_developer_lanes",
        ),
        (
            "profile-falcon-devnet",
            LatticeSignatureFamily::Falcon,
            "falcon-1024-abstract",
            11,
            1330,
            "compact_signature_contract_lane",
        ),
        (
            "profile-sphincs-devnet",
            LatticeSignatureFamily::SphincsLike,
            "slh-dsa-shake-256f-abstract",
            38,
            49856,
            "stateless_high_assurance_developer_lane",
        ),
    ];
    for (id, family, params, weight, bytes, hint) in profiles {
        state.profiles.insert(
            id.to_string(),
            LatticeProfileMetadata {
                profile_id: id.to_string(),
                family,
                parameter_set: params.to_string(),
                abstract_public_key_commitment: format!("{id}-public-key-commitment"),
                abstract_signature_commitment: format!("{id}-signature-commitment"),
                transcript_domain: format!("nebula-{id}-transcript-domain"),
                security_bits: 256,
                estimated_verify_weight: weight,
                max_signature_bytes: bytes,
                aggregation_hint: hint.to_string(),
                side_channel_notes_commitment: format!("{id}-side-channel-notes-root"),
                active_from_height: state.current_height,
                retired_at_height: None,
            },
        );
    }
    state.counters.profile_count = state.profiles.len() as u64;
    let budget_specs = [
        (
            "budget-operator-devnet",
            VerificationLane::Operator,
            DEFAULT_REDACTION_BUDGET_UNITS,
            DEFAULT_MIN_PRIVACY_SET,
        ),
        (
            "budget-developer-devnet",
            VerificationLane::Developer,
            DEFAULT_REDACTION_BUDGET_UNITS / 2,
            DEFAULT_MIN_PRIVACY_SET,
        ),
        (
            "budget-contract-devnet",
            VerificationLane::Contract,
            DEFAULT_REDACTION_BUDGET_UNITS,
            DEFAULT_MIN_PRIVACY_SET * 2,
        ),
    ];
    for (budget_id, lane, units, privacy_set) in budget_specs {
        state.privacy_budgets.insert(
            budget_id.to_string(),
            PrivacyRedactionBudget {
                budget_id: budget_id.to_string(),
                lane,
                owner_commitment: format!("{budget_id}-owner-commitment"),
                allowed_public_fields: BTreeSet::from([
                    "batch_id".to_string(),
                    "lane".to_string(),
                    "profile_id".to_string(),
                    "item_count".to_string(),
                    "status".to_string(),
                ]),
                redacted_field_commitment_root: format!("{budget_id}-redacted-field-root"),
                budget_units: units,
                consumed_units: 0,
                min_privacy_set: privacy_set,
                renewal_height: state.current_height + 10080,
            },
        );
    }
    state.counters.privacy_budget_count = state.privacy_budgets.len() as u64;
    let verifier_profiles = BTreeSet::from([
        "profile-ml-dsa-devnet".to_string(),
        "profile-falcon-devnet".to_string(),
        "profile-sphincs-devnet".to_string(),
    ]);
    for index in 0..4 {
        let verifier_id = format!("verifier-devnet-{index:02}");
        let lanes = if index == 0 {
            BTreeSet::from([
                VerificationLane::Operator,
                VerificationLane::Developer,
                VerificationLane::Contract,
            ])
        } else if index == 1 {
            BTreeSet::from([VerificationLane::Operator, VerificationLane::Contract])
        } else {
            BTreeSet::from([VerificationLane::Developer, VerificationLane::Contract])
        };
        state.verifiers.insert(
            verifier_id.clone(),
            VerifierRegistryEntry {
                verifier_id,
                operator_commitment: format!("operator-commitment-devnet-{index:02}"),
                lane_authorizations: lanes,
                supported_profiles: verifier_profiles.clone(),
                status: VerifierStatus::Active,
                stake_commitment: format!("stake-commitment-devnet-{index:02}"),
                endpoint_commitment: format!("endpoint-commitment-devnet-{index:02}"),
                locality_hint: format!("region-{index}"),
                max_parallel_batches: 64,
                low_fee_score: 900 + index as u64 * 10,
                privacy_score: 950 + index as u64 * 8,
                registered_height: state.current_height,
                last_heartbeat_height: state.current_height,
            },
        );
    }
    state.counters.verifier_count = state.verifiers.len() as u64;
    state.push_event(
        EventKind::ProfileCommitted,
        None,
        "profile-ml-dsa-devnet".to_string(),
    );
    state.push_event(
        EventKind::ProfileCommitted,
        None,
        "profile-falcon-devnet".to_string(),
    );
    state.push_event(
        EventKind::ProfileCommitted,
        None,
        "profile-sphincs-devnet".to_string(),
    );
    state.push_event(
        EventKind::VerifierRegistered,
        None,
        "verifier-devnet-00".to_string(),
    );
    state.push_event(
        EventKind::VerifierRegistered,
        None,
        "verifier-devnet-01".to_string(),
    );
    state.refresh_roots();
}

fn redaction_units(lane: VerificationLane, item_count: u64) -> u64 {
    let lane_factor = match lane {
        VerificationLane::Operator => 5,
        VerificationLane::Developer => 3,
        VerificationLane::Contract => 4,
    };
    item_count.saturating_mul(lane_factor)
}
fn root_from_values(domain: &str, values: Vec<Value>) -> String {
    let leaves = values
        .iter()
        .enumerate()
        .map(|(index, value)| stable_id(&format!("{domain}:{index}"), &stable_json(value)))
        .collect::<Vec<_>>();
    stable_id(domain, &stable_json(&json!(leaves)))
}
fn stable_id(domain: &str, payload: &str) -> String {
    let mut hasher = StableHasher::new();
    domain.hash(&mut hasher);
    payload.hash(&mut hasher);
    format!("{domain}-{:016x}", hasher.finish())
}
fn stable_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(item) => item.to_string(),
        Value::Number(item) => item.to_string(),
        Value::String(item) => format!("{:?}", item),
        Value::Array(items) => {
            let inner = items.iter().map(stable_json).collect::<Vec<_>>().join(",");
            format!("[{inner}]")
        }
        Value::Object(items) => {
            let inner = items
                .iter()
                .map(|(key, value)| format!("{:?}:{}", key, stable_json(value)))
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{inner}}}")
        }
    }
}
struct StableHasher(u64);
impl StableHasher {
    fn new() -> Self {
        Self(0xcbf29ce484222325)
    }
}
impl Hasher for StableHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_001: &str = "generated-policy-note-001-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail001 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail001 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_002: &str = "generated-policy-note-002-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail002 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail002 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_003: &str = "generated-policy-note-003-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail003 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail003 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_004: &str = "generated-policy-note-004-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail004 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail004 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_005: &str = "generated-policy-note-005-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail005 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail005 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_006: &str = "generated-policy-note-006-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail006 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail006 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_007: &str = "generated-policy-note-007-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail007 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail007 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_008: &str = "generated-policy-note-008-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail008 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail008 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_009: &str = "generated-policy-note-009-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail009 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail009 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_010: &str = "generated-policy-note-010-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail010 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail010 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_011: &str = "generated-policy-note-011-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail011 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail011 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_012: &str = "generated-policy-note-012-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail012 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail012 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_013: &str = "generated-policy-note-013-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail013 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail013 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_014: &str = "generated-policy-note-014-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail014 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail014 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_015: &str = "generated-policy-note-015-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail015 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail015 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_016: &str = "generated-policy-note-016-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail016 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail016 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_017: &str = "generated-policy-note-017-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail017 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail017 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_018: &str = "generated-policy-note-018-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail018 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail018 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_019: &str = "generated-policy-note-019-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail019 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail019 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_020: &str = "generated-policy-note-020-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail020 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail020 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_021: &str = "generated-policy-note-021-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail021 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail021 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_022: &str = "generated-policy-note-022-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail022 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail022 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_023: &str = "generated-policy-note-023-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail023 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail023 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_024: &str = "generated-policy-note-024-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail024 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail024 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_025: &str = "generated-policy-note-025-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail025 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail025 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_026: &str = "generated-policy-note-026-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail026 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail026 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}

pub const GENERATED_LATTICE_BATCH_POLICY_NOTE_027: &str = "generated-policy-note-027-roots-only-lattice-batch-verifier-redacts-raw-messages-signatures-and-keys";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedLaneGuardrail027 {
    pub guardrail_id: String,
    pub lane: VerificationLane,
    pub profile_family: LatticeSignatureFamily,
    pub max_items: u64,
    pub max_fee_micronero: u64,
    pub requires_quorum: bool,
    pub requires_privacy_budget: bool,
    pub note_commitment: String,
}
impl GeneratedLaneGuardrail027 {
    pub fn public_record(&self) -> Value {
        json!({ "guardrail_id": self.guardrail_id, "lane": self.lane.as_str(), "profile_family": self.profile_family.as_str(), "max_items": self.max_items, "max_fee_micronero": self.max_fee_micronero, "requires_quorum": self.requires_quorum, "requires_privacy_budget": self.requires_privacy_budget, "note_commitment": self.note_commitment })
    }
}
