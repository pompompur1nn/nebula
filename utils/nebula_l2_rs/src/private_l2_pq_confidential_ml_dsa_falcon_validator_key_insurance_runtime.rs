use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialMlDsaFalconValidatorKeyInsuranceRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_ML_DSA_FALCON_VALIDATOR_KEY_INSURANCE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-ml-dsa-falcon-validator-key-insurance-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_ML_DSA_FALCON_VALIDATOR_KEY_INSURANCE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ML_DSA_SUITE: &str = "ML-DSA-87-validator-key-insurance-v1";
pub const FALCON_SUITE: &str = "Falcon-1024-validator-key-insurance-v1";
pub const HYBRID_INSURANCE_AUTH_SUITE: &str =
    "ML-DSA-87+Falcon-1024-validator-key-insurance-hybrid-v1";
pub const PRIVATE_ROLLOVER_BUCKET_SUITE: &str =
    "confidential-validator-key-insurance-rollover-bucket-root-v1";
pub const EMERGENCY_RETIREMENT_SUITE: &str = "ml-dsa-falcon-validator-key-emergency-retirement-v1";
pub const LOW_FEE_DISPUTE_BATCH_SUITE: &str = "low-fee-validator-key-insurance-dispute-batch-v1";
pub const DEVNET_HEIGHT: u64 = 8_360_000;
pub const DEVNET_EPOCH: u64 = 34_875;
pub const DEVNET_SLOT: u64 = 512;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_COMMITTEE_SIZE: u16 = 17;
pub const DEFAULT_INSURANCE_THRESHOLD: u16 = 12;
pub const DEFAULT_PREMIUM_ATOMIC: u64 = 1_250_000_000;
pub const DEFAULT_COVERAGE_ATOMIC: u64 = 40_000_000_000;
pub const DEFAULT_BUCKET_TARGET_KEYS: u64 = 32_768;
pub const DEFAULT_MAX_BUCKETS_PER_EPOCH: u16 = 40;
pub const DEFAULT_MAX_DISPUTE_BATCH_SIZE: u16 = 160;
pub const DEFAULT_MAX_DISPUTE_FEE_MICRO_UNITS: u64 = 375;
pub const DEFAULT_RETIREMENT_WINDOW_SLOTS: u64 = 480;
pub const DEFAULT_ROLLOVER_GRACE_SLOTS: u64 = 1_440;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Active,
    RolloverPending,
    Bucketed,
    Disputed,
    Retired,
    Claimed,
    Expired,
}

impl PolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::RolloverPending => "rollover_pending",
            Self::Bucketed => "bucketed",
            Self::Disputed => "disputed",
            Self::Retired => "retired",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloverBucketStatus {
    Collecting,
    Sealed,
    DisputeWindowOpen,
    RetirementAnchored,
    Finalized,
}

impl RolloverBucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Sealed => "sealed",
            Self::DisputeWindowOpen => "dispute_window_open",
            Self::RetirementAnchored => "retirement_anchored",
            Self::Finalized => "finalized",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetirementStatus {
    Submitted,
    CommitteeAttested,
    EmergencyAccepted,
    Quarantined,
    Rejected,
}

impl RetirementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::CommitteeAttested => "committee_attested",
            Self::EmergencyAccepted => "emergency_accepted",
            Self::Quarantined => "quarantined",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeStatus {
    Submitted,
    Batched,
    EvidenceAccepted,
    EvidenceRejected,
    Resolved,
}

impl DisputeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Batched => "batched",
            Self::EvidenceAccepted => "evidence_accepted",
            Self::EvidenceRejected => "evidence_rejected",
            Self::Resolved => "resolved",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub network: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub ml_dsa_suite: String,
    pub falcon_suite: String,
    pub hybrid_insurance_auth_suite: String,
    pub private_rollover_bucket_suite: String,
    pub emergency_retirement_suite: String,
    pub low_fee_dispute_batch_suite: String,
    pub min_pq_security_bits: u16,
    pub committee_size: u16,
    pub insurance_threshold: u16,
    pub premium_atomic: u64,
    pub coverage_atomic: u64,
    pub bucket_target_keys: u64,
    pub max_buckets_per_epoch: u16,
    pub max_dispute_batch_size: u16,
    pub max_dispute_fee_micro_units: u64,
    pub retirement_window_slots: u64,
    pub rollover_grace_slots: u64,
    pub confidential_rollover_required: bool,
    pub emergency_retirement_enabled: bool,
    pub low_fee_dispute_batching_enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            network: "nebula-private-l2-devnet".to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            ml_dsa_suite: ML_DSA_SUITE.to_string(),
            falcon_suite: FALCON_SUITE.to_string(),
            hybrid_insurance_auth_suite: HYBRID_INSURANCE_AUTH_SUITE.to_string(),
            private_rollover_bucket_suite: PRIVATE_ROLLOVER_BUCKET_SUITE.to_string(),
            emergency_retirement_suite: EMERGENCY_RETIREMENT_SUITE.to_string(),
            low_fee_dispute_batch_suite: LOW_FEE_DISPUTE_BATCH_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            committee_size: DEFAULT_COMMITTEE_SIZE,
            insurance_threshold: DEFAULT_INSURANCE_THRESHOLD,
            premium_atomic: DEFAULT_PREMIUM_ATOMIC,
            coverage_atomic: DEFAULT_COVERAGE_ATOMIC,
            bucket_target_keys: DEFAULT_BUCKET_TARGET_KEYS,
            max_buckets_per_epoch: DEFAULT_MAX_BUCKETS_PER_EPOCH,
            max_dispute_batch_size: DEFAULT_MAX_DISPUTE_BATCH_SIZE,
            max_dispute_fee_micro_units: DEFAULT_MAX_DISPUTE_FEE_MICRO_UNITS,
            retirement_window_slots: DEFAULT_RETIREMENT_WINDOW_SLOTS,
            rollover_grace_slots: DEFAULT_ROLLOVER_GRACE_SLOTS,
            confidential_rollover_required: true,
            emergency_retirement_enabled: true,
            low_fee_dispute_batching_enabled: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below validator key insurance minimum".to_string());
        }
        if self.insurance_threshold == 0 || self.insurance_threshold > self.committee_size {
            return Err("invalid validator key insurance threshold".to_string());
        }
        if self.premium_atomic == 0 || self.coverage_atomic <= self.premium_atomic {
            return Err("invalid validator key insurance economics".to_string());
        }
        if self.bucket_target_keys == 0 || self.max_buckets_per_epoch == 0 {
            return Err("private rollover bucket limits must be positive".to_string());
        }
        if self.max_dispute_batch_size == 0 {
            return Err("low-fee insurance dispute batch size must be positive".to_string());
        }
        if self.retirement_window_slots == 0
            || self.retirement_window_slots > self.rollover_grace_slots
        {
            return Err("invalid emergency retirement window".to_string());
        }
        if !self.confidential_rollover_required {
            return Err("confidential validator key rollover must remain enabled".to_string());
        }
        if !self.emergency_retirement_enabled {
            return Err("emergency validator key retirement must remain enabled".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub insurance_policies: u64,
    pub rollover_buckets: u64,
    pub emergency_retirements: u64,
    pub insurance_disputes: u64,
    pub dispute_batches: u64,
    pub committee_attestations: u64,
    pub active_policies: u64,
    pub retired_keys: u64,
    pub claimed_policies: u64,
    pub total_premium_atomic: u64,
    pub total_coverage_atomic: u64,
    pub total_dispute_fee_micro_units: u64,
    pub private_bucket_key_total: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub insurance_policy_root: String,
    pub rollover_bucket_root: String,
    pub emergency_retirement_root: String,
    pub insurance_dispute_root: String,
    pub dispute_batch_root: String,
    pub committee_attestation_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ValidatorKeyInsurancePolicy {
    pub policy_id: String,
    pub validator_commitment: String,
    pub operator_commitment: String,
    pub insured_key_commitment: String,
    pub rollover_nullifier: String,
    pub premium_atomic: u64,
    pub coverage_atomic: u64,
    pub effective_epoch: u64,
    pub expires_epoch: u64,
    pub ml_dsa_policy_signature_root: String,
    pub falcon_policy_signature_root: String,
    pub status: PolicyStatus,
}

impl ValidatorKeyInsurancePolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "validator_commitment": self.validator_commitment,
            "operator_commitment": self.operator_commitment,
            "insured_key_commitment": self.insured_key_commitment,
            "rollover_nullifier": self.rollover_nullifier,
            "premium_atomic": self.premium_atomic,
            "coverage_atomic": self.coverage_atomic,
            "effective_epoch": self.effective_epoch,
            "expires_epoch": self.expires_epoch,
            "ml_dsa_policy_signature_root": self.ml_dsa_policy_signature_root,
            "falcon_policy_signature_root": self.falcon_policy_signature_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateRolloverBucket {
    pub bucket_id: String,
    pub epoch: u64,
    pub encrypted_rollover_bucket_root: String,
    pub insured_key_commitment_root: String,
    pub rollover_nullifier_root: String,
    pub policy_commitment_root: String,
    pub key_count: u64,
    pub status: RolloverBucketStatus,
}

impl PrivateRolloverBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "epoch": self.epoch,
            "encrypted_rollover_bucket_root": self.encrypted_rollover_bucket_root,
            "insured_key_commitment_root": self.insured_key_commitment_root,
            "rollover_nullifier_root": self.rollover_nullifier_root,
            "policy_commitment_root": self.policy_commitment_root,
            "key_count": self.key_count,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EmergencyKeyRetirement {
    pub retirement_id: String,
    pub policy_id: String,
    pub bucket_id: String,
    pub compromised_key_root: String,
    pub replacement_key_root: String,
    pub ml_dsa_retirement_signature_root: String,
    pub falcon_retirement_signature_root: String,
    pub zero_knowledge_transcript_root: String,
    pub pq_security_bits: u16,
    pub retirement_slot: u64,
    pub status: RetirementStatus,
}

impl EmergencyKeyRetirement {
    pub fn public_record(&self) -> Value {
        json!({
            "retirement_id": self.retirement_id,
            "policy_id": self.policy_id,
            "bucket_id": self.bucket_id,
            "compromised_key_root": self.compromised_key_root,
            "replacement_key_root": self.replacement_key_root,
            "ml_dsa_retirement_signature_root": self.ml_dsa_retirement_signature_root,
            "falcon_retirement_signature_root": self.falcon_retirement_signature_root,
            "zero_knowledge_transcript_root": self.zero_knowledge_transcript_root,
            "pq_security_bits": self.pq_security_bits,
            "retirement_slot": self.retirement_slot,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InsuranceDispute {
    pub dispute_id: String,
    pub policy_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub claimed_fault_root: String,
    pub fee_micro_units: u64,
    pub status: DisputeStatus,
}

impl InsuranceDispute {
    pub fn public_record(&self) -> Value {
        json!({
            "dispute_id": self.dispute_id,
            "policy_id": self.policy_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "claimed_fault_root": self.claimed_fault_root,
            "fee_micro_units": self.fee_micro_units,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeInsuranceDisputeBatch {
    pub batch_id: String,
    pub epoch: u64,
    pub dispute_ids: BTreeSet<String>,
    pub aggregate_fee_micro_units: u64,
    pub per_dispute_fee_micro_units: u64,
    pub batch_transcript_root: String,
    pub compression_commitment_root: String,
}

impl LowFeeInsuranceDisputeBatch {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitteeAttestation {
    pub attestation_id: String,
    pub committee_member_id: String,
    pub retirement_id: String,
    pub ml_dsa_attestation_root: String,
    pub falcon_attestation_root: String,
    pub observed_state_root: String,
    pub attested_slot: u64,
    pub accepted: bool,
}

impl CommitteeAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub slot: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub insurance_policies: BTreeMap<String, ValidatorKeyInsurancePolicy>,
    pub rollover_buckets: BTreeMap<String, PrivateRolloverBucket>,
    pub emergency_retirements: BTreeMap<String, EmergencyKeyRetirement>,
    pub insurance_disputes: BTreeMap<String, InsuranceDispute>,
    pub dispute_batches: BTreeMap<String, LowFeeInsuranceDisputeBatch>,
    pub committee_attestations: BTreeMap<String, CommitteeAttestation>,
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64, slot: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            height,
            epoch,
            slot,
            counters: Counters::default(),
            roots: Roots::default(),
            insurance_policies: BTreeMap::new(),
            rollover_buckets: BTreeMap::new(),
            emergency_retirements: BTreeMap::new(),
            insurance_disputes: BTreeMap::new(),
            dispute_batches: BTreeMap::new(),
            committee_attestations: BTreeMap::new(),
        };
        state.refresh();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT, DEVNET_EPOCH, DEVNET_SLOT)
            .unwrap_or_else(|_| Self::empty_devnet());
        state.seed_devnet();
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    fn seed_devnet(&mut self) {
        let bucket_id = deterministic_id(
            "rollover-bucket",
            &[HashPart::U64(self.epoch), HashPart::U64(0)],
        );
        self.rollover_buckets.insert(
            bucket_id.clone(),
            PrivateRolloverBucket {
                bucket_id: bucket_id.clone(),
                epoch: self.epoch,
                encrypted_rollover_bucket_root: sample_root("encrypted-rollover-bucket", 0),
                insured_key_commitment_root: sample_root("insured-key-commitment-set", 0),
                rollover_nullifier_root: sample_root("insurance-rollover-nullifier-set", 0),
                policy_commitment_root: sample_root("validator-key-policy-commitment-set", 0),
                key_count: self.config.bucket_target_keys,
                status: RolloverBucketStatus::RetirementAnchored,
            },
        );

        for index in 0_u64..4 {
            let policy_id = deterministic_id(
                "insurance-policy",
                &[HashPart::U64(self.epoch), HashPart::U64(index)],
            );
            let status = match index {
                0 | 1 => PolicyStatus::Retired,
                2 => PolicyStatus::Claimed,
                _ => PolicyStatus::Active,
            };
            self.insurance_policies.insert(
                policy_id.clone(),
                ValidatorKeyInsurancePolicy {
                    policy_id: policy_id.clone(),
                    validator_commitment: sample_root("insured-validator-commitment", index),
                    operator_commitment: sample_root("insurance-operator-commitment", index),
                    insured_key_commitment: sample_root("insured-validator-key", index),
                    rollover_nullifier: sample_root("validator-key-rollover-nullifier", index),
                    premium_atomic: self.config.premium_atomic,
                    coverage_atomic: self.config.coverage_atomic,
                    effective_epoch: self.epoch,
                    expires_epoch: self.epoch + 16,
                    ml_dsa_policy_signature_root: sample_root("ml-dsa-policy-signature", index),
                    falcon_policy_signature_root: sample_root("falcon-policy-signature", index),
                    status,
                },
            );

            let retirement_id = deterministic_id(
                "emergency-retirement",
                &[HashPart::Str(&policy_id), HashPart::Str(&bucket_id)],
            );
            self.emergency_retirements.insert(
                retirement_id.clone(),
                EmergencyKeyRetirement {
                    retirement_id,
                    policy_id: policy_id.clone(),
                    bucket_id: bucket_id.clone(),
                    compromised_key_root: sample_root("compromised-validator-key", index),
                    replacement_key_root: sample_root("replacement-validator-key", index),
                    ml_dsa_retirement_signature_root: sample_root(
                        "ml-dsa-emergency-retirement-signature",
                        index,
                    ),
                    falcon_retirement_signature_root: sample_root(
                        "falcon-emergency-retirement-signature",
                        index,
                    ),
                    zero_knowledge_transcript_root: sample_root(
                        "validator-key-insurance-zk-transcript",
                        index,
                    ),
                    pq_security_bits: self.config.min_pq_security_bits,
                    retirement_slot: self.slot + index * 8,
                    status: RetirementStatus::EmergencyAccepted,
                },
            );
        }

        for index in 0_u64..2 {
            let policy_id = self
                .insurance_policies
                .keys()
                .nth(index as usize)
                .cloned()
                .unwrap_or_else(|| sample_root("missing-policy", index));
            let dispute_id = deterministic_id(
                "insurance-dispute",
                &[HashPart::Str(&policy_id), HashPart::U64(index)],
            );
            self.insurance_disputes.insert(
                dispute_id.clone(),
                InsuranceDispute {
                    dispute_id,
                    policy_id,
                    challenger_commitment: sample_root("insurance-dispute-challenger", index),
                    evidence_root: sample_root("insurance-dispute-evidence", index),
                    claimed_fault_root: sample_root("validator-key-insurance-fault", index),
                    fee_micro_units: 85 + index * 15,
                    status: DisputeStatus::Resolved,
                },
            );
        }

        let dispute_ids = self
            .insurance_disputes
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let batch_id = deterministic_id(
            "low-fee-dispute-batch",
            &[
                HashPart::U64(self.epoch),
                HashPart::U64(dispute_ids.len() as u64),
            ],
        );
        self.dispute_batches.insert(
            batch_id.clone(),
            LowFeeInsuranceDisputeBatch {
                batch_id,
                epoch: self.epoch,
                dispute_ids,
                aggregate_fee_micro_units: 185,
                per_dispute_fee_micro_units: 93,
                batch_transcript_root: sample_root("low-fee-insurance-dispute-batch", 0),
                compression_commitment_root: sample_root("insurance-dispute-compression", 0),
            },
        );

        for index in 0..self.config.insurance_threshold {
            let retirement_id = self
                .emergency_retirements
                .keys()
                .next()
                .cloned()
                .unwrap_or_else(|| sample_root("missing-retirement", u64::from(index)));
            let attestation_id = deterministic_id(
                "committee-attestation",
                &[
                    HashPart::Str(&retirement_id),
                    HashPart::U64(u64::from(index)),
                ],
            );
            self.committee_attestations.insert(
                attestation_id.clone(),
                CommitteeAttestation {
                    attestation_id,
                    committee_member_id: format!(
                        "validator-key-insurance-committee-devnet-{index:04}"
                    ),
                    retirement_id,
                    ml_dsa_attestation_root: sample_root(
                        "ml-dsa-insurance-attestation",
                        u64::from(index),
                    ),
                    falcon_attestation_root: sample_root(
                        "falcon-insurance-attestation",
                        u64::from(index),
                    ),
                    observed_state_root: sample_root(
                        "validator-key-insurance-observed-state",
                        u64::from(index),
                    ),
                    attested_slot: self.slot + 40 + u64::from(index),
                    accepted: true,
                },
            );
        }
        self.refresh();
    }

    fn refresh(&mut self) {
        self.counters = Counters {
            insurance_policies: self.insurance_policies.len() as u64,
            rollover_buckets: self.rollover_buckets.len() as u64,
            emergency_retirements: self.emergency_retirements.len() as u64,
            insurance_disputes: self.insurance_disputes.len() as u64,
            dispute_batches: self.dispute_batches.len() as u64,
            committee_attestations: self.committee_attestations.len() as u64,
            active_policies: self
                .insurance_policies
                .values()
                .filter(|policy| policy.status == PolicyStatus::Active)
                .count() as u64,
            retired_keys: self
                .emergency_retirements
                .values()
                .filter(|retirement| retirement.status == RetirementStatus::EmergencyAccepted)
                .count() as u64,
            claimed_policies: self
                .insurance_policies
                .values()
                .filter(|policy| policy.status == PolicyStatus::Claimed)
                .count() as u64,
            total_premium_atomic: self
                .insurance_policies
                .values()
                .map(|policy| policy.premium_atomic)
                .sum(),
            total_coverage_atomic: self
                .insurance_policies
                .values()
                .map(|policy| policy.coverage_atomic)
                .sum(),
            total_dispute_fee_micro_units: self
                .insurance_disputes
                .values()
                .map(|dispute| dispute.fee_micro_units)
                .sum(),
            private_bucket_key_total: self
                .rollover_buckets
                .values()
                .map(|bucket| bucket.key_count)
                .sum(),
        };
        self.roots = self.compute_roots();
    }

    fn compute_roots(&self) -> Roots {
        let insurance_policy_root = record_root(
            "insurance-policies",
            self.insurance_policies
                .values()
                .map(ValidatorKeyInsurancePolicy::public_record)
                .collect(),
        );
        let rollover_bucket_root = record_root(
            "rollover-buckets",
            self.rollover_buckets
                .values()
                .map(PrivateRolloverBucket::public_record)
                .collect(),
        );
        let emergency_retirement_root = record_root(
            "emergency-retirements",
            self.emergency_retirements
                .values()
                .map(EmergencyKeyRetirement::public_record)
                .collect(),
        );
        let insurance_dispute_root = record_root(
            "insurance-disputes",
            self.insurance_disputes
                .values()
                .map(InsuranceDispute::public_record)
                .collect(),
        );
        let dispute_batch_root = record_root(
            "dispute-batches",
            self.dispute_batches
                .values()
                .map(LowFeeInsuranceDisputeBatch::public_record)
                .collect(),
        );
        let committee_attestation_root = record_root(
            "committee-attestations",
            self.committee_attestations
                .values()
                .map(CommitteeAttestation::public_record)
                .collect(),
        );
        let public_record_root = value_root(
            "public-record",
            &json!({
                "config": self.config.public_record(),
                "counters": self.counters.public_record(),
                "insurance_policy_root": insurance_policy_root,
                "rollover_bucket_root": rollover_bucket_root,
                "emergency_retirement_root": emergency_retirement_root,
                "insurance_dispute_root": insurance_dispute_root,
                "dispute_batch_root": dispute_batch_root,
                "committee_attestation_root": committee_attestation_root,
            }),
        );
        let state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-ML-DSA-FALCON-VALIDATOR-KEY-INSURANCE-STATE",
            &[
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Str(&insurance_policy_root),
                HashPart::Str(&rollover_bucket_root),
                HashPart::Str(&emergency_retirement_root),
                HashPart::Str(&insurance_dispute_root),
                HashPart::Str(&dispute_batch_root),
                HashPart::Str(&committee_attestation_root),
                HashPart::Str(&public_record_root),
                HashPart::U64(self.height),
                HashPart::U64(self.epoch),
                HashPart::U64(self.slot),
            ],
            32,
        );
        Roots {
            insurance_policy_root,
            rollover_bucket_root,
            emergency_retirement_root,
            insurance_dispute_root,
            dispute_batch_root,
            committee_attestation_root,
            public_record_root,
            state_root,
        }
    }

    fn empty_devnet() -> Self {
        Self {
            config: Config::devnet(),
            height: DEVNET_HEIGHT,
            epoch: DEVNET_EPOCH,
            slot: DEVNET_SLOT,
            counters: Counters::default(),
            roots: Roots::default(),
            insurance_policies: BTreeMap::new(),
            rollover_buckets: BTreeMap::new(),
            emergency_retirements: BTreeMap::new(),
            insurance_disputes: BTreeMap::new(),
            dispute_batches: BTreeMap::new(),
            committee_attestations: BTreeMap::new(),
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    json!({
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "height": state.height,
        "epoch": state.epoch,
        "slot": state.slot,
        "hash_suite": HASH_SUITE,
        "ml_dsa_suite": ML_DSA_SUITE,
        "falcon_suite": FALCON_SUITE,
        "hybrid_insurance_auth_suite": HYBRID_INSURANCE_AUTH_SUITE,
        "private_rollover_bucket_suite": PRIVATE_ROLLOVER_BUCKET_SUITE,
        "emergency_retirement_suite": EMERGENCY_RETIREMENT_SUITE,
        "low_fee_dispute_batch_suite": LOW_FEE_DISPUTE_BATCH_SUITE,
        "config": state.config.public_record(),
        "counters": state.counters.public_record(),
        "roots": state.roots.public_record(),
        "insurance_policies": state
            .insurance_policies
            .values()
            .map(ValidatorKeyInsurancePolicy::public_record)
            .collect::<Vec<_>>(),
        "rollover_buckets": state
            .rollover_buckets
            .values()
            .map(PrivateRolloverBucket::public_record)
            .collect::<Vec<_>>(),
        "emergency_retirements": state
            .emergency_retirements
            .values()
            .map(EmergencyKeyRetirement::public_record)
            .collect::<Vec<_>>(),
        "insurance_disputes": state
            .insurance_disputes
            .values()
            .map(InsuranceDispute::public_record)
            .collect::<Vec<_>>(),
        "dispute_batches": state
            .dispute_batches
            .values()
            .map(LowFeeInsuranceDisputeBatch::public_record)
            .collect::<Vec<_>>(),
        "committee_attestations": state
            .committee_attestations
            .values()
            .map(CommitteeAttestation::public_record)
            .collect::<Vec<_>>(),
        "state_root": state.state_root(),
    })
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-ML-DSA-FALCON-VALIDATOR-KEY-INSURANCE-{domain}-ID"),
        parts,
        24,
    )
}

pub fn sample_root(label: &str, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-ML-DSA-FALCON-VALIDATOR-KEY-INSURANCE-DEVNET-SAMPLE",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

pub fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-ML-DSA-FALCON-VALIDATOR-KEY-INSURANCE-{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}

pub fn record_root(domain: &str, mut values: Vec<Value>) -> String {
    values.sort_by_key(|value| value.to_string());
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-ML-DSA-FALCON-VALIDATOR-KEY-INSURANCE-{domain}"),
        &values,
    )
}
