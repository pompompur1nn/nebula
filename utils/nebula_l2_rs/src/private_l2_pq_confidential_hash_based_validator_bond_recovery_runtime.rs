use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialHashBasedValidatorBondRecoveryRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_HASH_BASED_VALIDATOR_BOND_RECOVERY_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-hash-based-validator-bond-recovery-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_HASH_BASED_VALIDATOR_BOND_RECOVERY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const HASH_BASED_RECOVERY_SUITE: &str = "hash-based-validator-bond-recovery-commitment-v1";
pub const SPHINCS_RECOVERY_PROOF_SUITE: &str =
    "SPHINCS+-SHAKE-256f-validator-bond-recovery-proof-v1";
pub const PRIVATE_VALIDATOR_BUCKET_SUITE: &str =
    "confidential-validator-bond-recovery-bucket-root-v1";
pub const LOW_FEE_CLAIM_BATCH_SUITE: &str =
    "low-fee-confidential-validator-bond-recovery-claim-batch-v1";
pub const RECOVERY_COMMITTEE_ATTESTATION_SUITE: &str =
    "hash-based-validator-bond-recovery-committee-attestation-v1";
pub const DEVNET_HEIGHT: u64 = 8_520_000;
pub const DEVNET_EPOCH: u64 = 35_542;
pub const DEVNET_SLOT: u64 = 704;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_COMMITTEE_SIZE: u16 = 21;
pub const DEFAULT_RECOVERY_THRESHOLD: u16 = 14;
pub const DEFAULT_VALIDATOR_BOND_ATOMIC: u64 = 32_000_000_000;
pub const DEFAULT_RECOVERY_COVERAGE_ATOMIC: u64 = 24_000_000_000;
pub const DEFAULT_RECOVERY_FEE_ATOMIC: u64 = 450_000_000;
pub const DEFAULT_BUCKET_TARGET_VALIDATORS: u64 = 28_672;
pub const DEFAULT_MAX_BUCKETS_PER_EPOCH: u16 = 48;
pub const DEFAULT_MAX_CLAIM_BATCH_SIZE: u16 = 256;
pub const DEFAULT_MAX_CLAIM_FEE_MICRO_UNITS: u64 = 275;
pub const DEFAULT_RECOVERY_WINDOW_SLOTS: u64 = 1_920;
pub const DEFAULT_PROOF_GRACE_SLOTS: u64 = 3_840;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPolicyStatus {
    Active,
    Bucketed,
    ProofPending,
    ProofAccepted,
    Claimed,
    Recovered,
    Expired,
}

impl RecoveryPolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Bucketed => "bucketed",
            Self::ProofPending => "proof_pending",
            Self::ProofAccepted => "proof_accepted",
            Self::Claimed => "claimed",
            Self::Recovered => "recovered",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorBucketStatus {
    Collecting,
    Sealed,
    RecoveryWindowOpen,
    ProofAnchored,
    Finalized,
}

impl ValidatorBucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Sealed => "sealed",
            Self::RecoveryWindowOpen => "recovery_window_open",
            Self::ProofAnchored => "proof_anchored",
            Self::Finalized => "finalized",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryProofStatus {
    Submitted,
    CommitteeAttested,
    Accepted,
    Quarantined,
    Rejected,
}

impl RecoveryProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::CommitteeAttested => "committee_attested",
            Self::Accepted => "accepted",
            Self::Quarantined => "quarantined",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Submitted,
    Batched,
    ProofAccepted,
    ProofRejected,
    Paid,
}

impl ClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Batched => "batched",
            Self::ProofAccepted => "proof_accepted",
            Self::ProofRejected => "proof_rejected",
            Self::Paid => "paid",
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
    pub hash_based_recovery_suite: String,
    pub sphincs_recovery_proof_suite: String,
    pub private_validator_bucket_suite: String,
    pub low_fee_claim_batch_suite: String,
    pub recovery_committee_attestation_suite: String,
    pub min_pq_security_bits: u16,
    pub committee_size: u16,
    pub recovery_threshold: u16,
    pub validator_bond_atomic: u64,
    pub recovery_coverage_atomic: u64,
    pub recovery_fee_atomic: u64,
    pub bucket_target_validators: u64,
    pub max_buckets_per_epoch: u16,
    pub max_claim_batch_size: u16,
    pub max_claim_fee_micro_units: u64,
    pub recovery_window_slots: u64,
    pub proof_grace_slots: u64,
    pub private_validator_buckets_required: bool,
    pub sphincs_recovery_proofs_required: bool,
    pub low_fee_claim_batching_enabled: bool,
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
            hash_based_recovery_suite: HASH_BASED_RECOVERY_SUITE.to_string(),
            sphincs_recovery_proof_suite: SPHINCS_RECOVERY_PROOF_SUITE.to_string(),
            private_validator_bucket_suite: PRIVATE_VALIDATOR_BUCKET_SUITE.to_string(),
            low_fee_claim_batch_suite: LOW_FEE_CLAIM_BATCH_SUITE.to_string(),
            recovery_committee_attestation_suite: RECOVERY_COMMITTEE_ATTESTATION_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            committee_size: DEFAULT_COMMITTEE_SIZE,
            recovery_threshold: DEFAULT_RECOVERY_THRESHOLD,
            validator_bond_atomic: DEFAULT_VALIDATOR_BOND_ATOMIC,
            recovery_coverage_atomic: DEFAULT_RECOVERY_COVERAGE_ATOMIC,
            recovery_fee_atomic: DEFAULT_RECOVERY_FEE_ATOMIC,
            bucket_target_validators: DEFAULT_BUCKET_TARGET_VALIDATORS,
            max_buckets_per_epoch: DEFAULT_MAX_BUCKETS_PER_EPOCH,
            max_claim_batch_size: DEFAULT_MAX_CLAIM_BATCH_SIZE,
            max_claim_fee_micro_units: DEFAULT_MAX_CLAIM_FEE_MICRO_UNITS,
            recovery_window_slots: DEFAULT_RECOVERY_WINDOW_SLOTS,
            proof_grace_slots: DEFAULT_PROOF_GRACE_SLOTS,
            private_validator_buckets_required: true,
            sphincs_recovery_proofs_required: true,
            low_fee_claim_batching_enabled: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below validator bond recovery minimum".to_string());
        }
        if self.recovery_threshold == 0 || self.recovery_threshold > self.committee_size {
            return Err("invalid validator bond recovery threshold".to_string());
        }
        if self.validator_bond_atomic == 0
            || self.recovery_fee_atomic == 0
            || self.recovery_coverage_atomic == 0
            || self.recovery_coverage_atomic > self.validator_bond_atomic
        {
            return Err("invalid validator bond recovery economics".to_string());
        }
        if self.bucket_target_validators == 0 || self.max_buckets_per_epoch == 0 {
            return Err("private validator bucket limits must be positive".to_string());
        }
        if self.max_claim_batch_size == 0 {
            return Err(
                "low-fee validator bond recovery claim batch size must be positive".to_string(),
            );
        }
        if self.recovery_window_slots == 0 || self.recovery_window_slots > self.proof_grace_slots {
            return Err("invalid validator bond recovery proof window".to_string());
        }
        if !self.private_validator_buckets_required {
            return Err("private validator buckets must remain enabled".to_string());
        }
        if !self.sphincs_recovery_proofs_required {
            return Err("sphincs-style recovery proofs must remain enabled".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub recovery_policies: u64,
    pub private_validator_buckets: u64,
    pub recovery_proofs: u64,
    pub recovery_claims: u64,
    pub claim_batches: u64,
    pub committee_attestations: u64,
    pub active_policies: u64,
    pub recovered_policies: u64,
    pub claimed_policies: u64,
    pub total_validator_bond_atomic: u64,
    pub total_recovery_coverage_atomic: u64,
    pub total_recovery_fee_atomic: u64,
    pub total_claim_fee_micro_units: u64,
    pub private_bucket_validator_total: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub recovery_policy_root: String,
    pub private_validator_bucket_root: String,
    pub recovery_proof_root: String,
    pub recovery_claim_root: String,
    pub claim_batch_root: String,
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
pub struct ValidatorBondRecoveryPolicy {
    pub policy_id: String,
    pub validator_commitment: String,
    pub operator_commitment: String,
    pub bond_commitment: String,
    pub recovery_key_commitment: String,
    pub recovery_nullifier: String,
    pub validator_bond_atomic: u64,
    pub recovery_coverage_atomic: u64,
    pub recovery_fee_atomic: u64,
    pub effective_epoch: u64,
    pub expires_epoch: u64,
    pub hash_ladder_root: String,
    pub sphincs_policy_signature_root: String,
    pub status: RecoveryPolicyStatus,
}

impl ValidatorBondRecoveryPolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "validator_commitment": self.validator_commitment,
            "operator_commitment": self.operator_commitment,
            "bond_commitment": self.bond_commitment,
            "recovery_key_commitment": self.recovery_key_commitment,
            "recovery_nullifier": self.recovery_nullifier,
            "validator_bond_atomic": self.validator_bond_atomic,
            "recovery_coverage_atomic": self.recovery_coverage_atomic,
            "recovery_fee_atomic": self.recovery_fee_atomic,
            "effective_epoch": self.effective_epoch,
            "expires_epoch": self.expires_epoch,
            "hash_ladder_root": self.hash_ladder_root,
            "sphincs_policy_signature_root": self.sphincs_policy_signature_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateValidatorBucket {
    pub bucket_id: String,
    pub epoch: u64,
    pub encrypted_validator_bucket_root: String,
    pub validator_commitment_root: String,
    pub bond_commitment_root: String,
    pub recovery_key_commitment_root: String,
    pub recovery_nullifier_root: String,
    pub policy_commitment_root: String,
    pub validator_count: u64,
    pub status: ValidatorBucketStatus,
}

impl PrivateValidatorBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "epoch": self.epoch,
            "encrypted_validator_bucket_root": self.encrypted_validator_bucket_root,
            "validator_commitment_root": self.validator_commitment_root,
            "bond_commitment_root": self.bond_commitment_root,
            "recovery_key_commitment_root": self.recovery_key_commitment_root,
            "recovery_nullifier_root": self.recovery_nullifier_root,
            "policy_commitment_root": self.policy_commitment_root,
            "validator_count": self.validator_count,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SphincsRecoveryProof {
    pub proof_id: String,
    pub policy_id: String,
    pub bucket_id: String,
    pub lost_bond_root: String,
    pub recovery_destination_root: String,
    pub recovery_path_root: String,
    pub hash_ladder_witness_root: String,
    pub sphincs_recovery_signature_root: String,
    pub zero_knowledge_transcript_root: String,
    pub pq_security_bits: u16,
    pub recovery_slot: u64,
    pub status: RecoveryProofStatus,
}

impl SphincsRecoveryProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "policy_id": self.policy_id,
            "bucket_id": self.bucket_id,
            "lost_bond_root": self.lost_bond_root,
            "recovery_destination_root": self.recovery_destination_root,
            "recovery_path_root": self.recovery_path_root,
            "hash_ladder_witness_root": self.hash_ladder_witness_root,
            "sphincs_recovery_signature_root": self.sphincs_recovery_signature_root,
            "zero_knowledge_transcript_root": self.zero_knowledge_transcript_root,
            "pq_security_bits": self.pq_security_bits,
            "recovery_slot": self.recovery_slot,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecoveryClaim {
    pub claim_id: String,
    pub policy_id: String,
    pub claimant_commitment: String,
    pub proof_root: String,
    pub bond_loss_event_root: String,
    pub payout_atomic: u64,
    pub fee_micro_units: u64,
    pub status: ClaimStatus,
}

impl RecoveryClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "policy_id": self.policy_id,
            "claimant_commitment": self.claimant_commitment,
            "proof_root": self.proof_root,
            "bond_loss_event_root": self.bond_loss_event_root,
            "payout_atomic": self.payout_atomic,
            "fee_micro_units": self.fee_micro_units,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRecoveryClaimBatch {
    pub batch_id: String,
    pub epoch: u64,
    pub claim_ids: BTreeSet<String>,
    pub aggregate_fee_micro_units: u64,
    pub per_claim_fee_micro_units: u64,
    pub batch_transcript_root: String,
    pub compression_commitment_root: String,
}

impl LowFeeRecoveryClaimBatch {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitteeAttestation {
    pub attestation_id: String,
    pub committee_member_id: String,
    pub proof_id: String,
    pub sphincs_attestation_root: String,
    pub hash_based_attestation_root: String,
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
    pub recovery_policies: BTreeMap<String, ValidatorBondRecoveryPolicy>,
    pub private_validator_buckets: BTreeMap<String, PrivateValidatorBucket>,
    pub recovery_proofs: BTreeMap<String, SphincsRecoveryProof>,
    pub recovery_claims: BTreeMap<String, RecoveryClaim>,
    pub claim_batches: BTreeMap<String, LowFeeRecoveryClaimBatch>,
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
            recovery_policies: BTreeMap::new(),
            private_validator_buckets: BTreeMap::new(),
            recovery_proofs: BTreeMap::new(),
            recovery_claims: BTreeMap::new(),
            claim_batches: BTreeMap::new(),
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
            "private-validator-bucket",
            &[HashPart::U64(self.epoch), HashPart::U64(0)],
        );
        self.private_validator_buckets.insert(
            bucket_id.clone(),
            PrivateValidatorBucket {
                bucket_id: bucket_id.clone(),
                epoch: self.epoch,
                encrypted_validator_bucket_root: sample_root("encrypted-validator-bucket", 0),
                validator_commitment_root: sample_root("validator-commitment-set", 0),
                bond_commitment_root: sample_root("validator-bond-commitment-set", 0),
                recovery_key_commitment_root: sample_root("recovery-key-commitment-set", 0),
                recovery_nullifier_root: sample_root("bond-recovery-nullifier-set", 0),
                policy_commitment_root: sample_root("bond-recovery-policy-commitment-set", 0),
                validator_count: self.config.bucket_target_validators,
                status: ValidatorBucketStatus::ProofAnchored,
            },
        );

        for index in 0_u64..4 {
            let policy_id = deterministic_id(
                "recovery-policy",
                &[HashPart::U64(self.epoch), HashPart::U64(index)],
            );
            let status = match index {
                0 | 1 => RecoveryPolicyStatus::ProofAccepted,
                2 => RecoveryPolicyStatus::Claimed,
                _ => RecoveryPolicyStatus::Active,
            };
            self.recovery_policies.insert(
                policy_id.clone(),
                ValidatorBondRecoveryPolicy {
                    policy_id: policy_id.clone(),
                    validator_commitment: sample_root("recovery-validator-commitment", index),
                    operator_commitment: sample_root("recovery-operator-commitment", index),
                    bond_commitment: sample_root("validator-bond-commitment", index),
                    recovery_key_commitment: sample_root("hash-based-recovery-key", index),
                    recovery_nullifier: sample_root("validator-bond-recovery-nullifier", index),
                    validator_bond_atomic: self.config.validator_bond_atomic,
                    recovery_coverage_atomic: self.config.recovery_coverage_atomic,
                    recovery_fee_atomic: self.config.recovery_fee_atomic,
                    effective_epoch: self.epoch,
                    expires_epoch: self.epoch + 10,
                    hash_ladder_root: sample_root("validator-bond-hash-ladder", index),
                    sphincs_policy_signature_root: sample_root(
                        "sphincs-recovery-policy-signature",
                        index,
                    ),
                    status,
                },
            );

            let proof_id = deterministic_id(
                "sphincs-recovery-proof",
                &[HashPart::Str(&policy_id), HashPart::Str(&bucket_id)],
            );
            self.recovery_proofs.insert(
                proof_id.clone(),
                SphincsRecoveryProof {
                    proof_id,
                    policy_id: policy_id.clone(),
                    bucket_id: bucket_id.clone(),
                    lost_bond_root: sample_root("lost-validator-bond", index),
                    recovery_destination_root: sample_root("bond-recovery-destination", index),
                    recovery_path_root: sample_root("validator-bond-recovery-path", index),
                    hash_ladder_witness_root: sample_root("hash-ladder-witness", index),
                    sphincs_recovery_signature_root: sample_root(
                        "sphincs-bond-recovery-signature",
                        index,
                    ),
                    zero_knowledge_transcript_root: sample_root(
                        "bond-recovery-zk-transcript",
                        index,
                    ),
                    pq_security_bits: self.config.min_pq_security_bits,
                    recovery_slot: self.slot + index * 10,
                    status: RecoveryProofStatus::Accepted,
                },
            );
        }

        for index in 0_u64..2 {
            let policy_id = self
                .recovery_policies
                .keys()
                .nth(index as usize)
                .cloned()
                .unwrap_or_else(|| sample_root("missing-policy", index));
            let claim_id = deterministic_id(
                "recovery-claim",
                &[HashPart::Str(&policy_id), HashPart::U64(index)],
            );
            self.recovery_claims.insert(
                claim_id.clone(),
                RecoveryClaim {
                    claim_id,
                    policy_id,
                    claimant_commitment: sample_root("bond-recovery-claimant", index),
                    proof_root: sample_root("bond-recovery-claim-proof", index),
                    bond_loss_event_root: sample_root("validator-bond-loss-event", index),
                    payout_atomic: self.config.recovery_coverage_atomic / 2,
                    fee_micro_units: 65 + index * 15,
                    status: ClaimStatus::Paid,
                },
            );
        }

        let claim_ids = self
            .recovery_claims
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let batch_id = deterministic_id(
            "low-fee-claim-batch",
            &[
                HashPart::U64(self.epoch),
                HashPart::U64(claim_ids.len() as u64),
            ],
        );
        self.claim_batches.insert(
            batch_id.clone(),
            LowFeeRecoveryClaimBatch {
                batch_id,
                epoch: self.epoch,
                claim_ids,
                aggregate_fee_micro_units: 145,
                per_claim_fee_micro_units: 73,
                batch_transcript_root: sample_root("low-fee-bond-recovery-claim-batch", 0),
                compression_commitment_root: sample_root("bond-recovery-claim-compression", 0),
            },
        );

        for index in 0..self.config.recovery_threshold {
            let proof_id = self
                .recovery_proofs
                .keys()
                .next()
                .cloned()
                .unwrap_or_else(|| sample_root("missing-recovery-proof", u64::from(index)));
            let attestation_id = deterministic_id(
                "committee-attestation",
                &[HashPart::Str(&proof_id), HashPart::U64(u64::from(index))],
            );
            self.committee_attestations.insert(
                attestation_id.clone(),
                CommitteeAttestation {
                    attestation_id,
                    committee_member_id: format!(
                        "validator-bond-recovery-committee-devnet-{index:04}"
                    ),
                    proof_id,
                    sphincs_attestation_root: sample_root(
                        "sphincs-bond-recovery-attestation",
                        u64::from(index),
                    ),
                    hash_based_attestation_root: sample_root(
                        "hash-based-bond-recovery-attestation",
                        u64::from(index),
                    ),
                    observed_state_root: sample_root(
                        "validator-bond-recovery-observed-state",
                        u64::from(index),
                    ),
                    attested_slot: self.slot + 48 + u64::from(index),
                    accepted: true,
                },
            );
        }
        self.refresh();
    }

    fn refresh(&mut self) {
        self.counters = Counters {
            recovery_policies: self.recovery_policies.len() as u64,
            private_validator_buckets: self.private_validator_buckets.len() as u64,
            recovery_proofs: self.recovery_proofs.len() as u64,
            recovery_claims: self.recovery_claims.len() as u64,
            claim_batches: self.claim_batches.len() as u64,
            committee_attestations: self.committee_attestations.len() as u64,
            active_policies: self
                .recovery_policies
                .values()
                .filter(|policy| policy.status == RecoveryPolicyStatus::Active)
                .count() as u64,
            recovered_policies: self
                .recovery_policies
                .values()
                .filter(|policy| policy.status == RecoveryPolicyStatus::Recovered)
                .count() as u64,
            claimed_policies: self
                .recovery_policies
                .values()
                .filter(|policy| policy.status == RecoveryPolicyStatus::Claimed)
                .count() as u64,
            total_validator_bond_atomic: self
                .recovery_policies
                .values()
                .map(|policy| policy.validator_bond_atomic)
                .sum(),
            total_recovery_coverage_atomic: self
                .recovery_policies
                .values()
                .map(|policy| policy.recovery_coverage_atomic)
                .sum(),
            total_recovery_fee_atomic: self
                .recovery_policies
                .values()
                .map(|policy| policy.recovery_fee_atomic)
                .sum(),
            total_claim_fee_micro_units: self
                .recovery_claims
                .values()
                .map(|claim| claim.fee_micro_units)
                .sum(),
            private_bucket_validator_total: self
                .private_validator_buckets
                .values()
                .map(|bucket| bucket.validator_count)
                .sum(),
        };
        self.roots = self.compute_roots();
    }

    fn compute_roots(&self) -> Roots {
        let recovery_policy_root = record_root(
            "recovery-policies",
            self.recovery_policies
                .values()
                .map(ValidatorBondRecoveryPolicy::public_record)
                .collect(),
        );
        let private_validator_bucket_root = record_root(
            "private-validator-buckets",
            self.private_validator_buckets
                .values()
                .map(PrivateValidatorBucket::public_record)
                .collect(),
        );
        let recovery_proof_root = record_root(
            "recovery-proofs",
            self.recovery_proofs
                .values()
                .map(SphincsRecoveryProof::public_record)
                .collect(),
        );
        let recovery_claim_root = record_root(
            "recovery-claims",
            self.recovery_claims
                .values()
                .map(RecoveryClaim::public_record)
                .collect(),
        );
        let claim_batch_root = record_root(
            "claim-batches",
            self.claim_batches
                .values()
                .map(LowFeeRecoveryClaimBatch::public_record)
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
                "recovery_policy_root": recovery_policy_root,
                "private_validator_bucket_root": private_validator_bucket_root,
                "recovery_proof_root": recovery_proof_root,
                "recovery_claim_root": recovery_claim_root,
                "claim_batch_root": claim_batch_root,
                "committee_attestation_root": committee_attestation_root,
            }),
        );
        let state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-HASH-BASED-VALIDATOR-BOND-RECOVERY-STATE",
            &[
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Str(&recovery_policy_root),
                HashPart::Str(&private_validator_bucket_root),
                HashPart::Str(&recovery_proof_root),
                HashPart::Str(&recovery_claim_root),
                HashPart::Str(&claim_batch_root),
                HashPart::Str(&committee_attestation_root),
                HashPart::Str(&public_record_root),
                HashPart::U64(self.height),
                HashPart::U64(self.epoch),
                HashPart::U64(self.slot),
            ],
            32,
        );
        Roots {
            recovery_policy_root,
            private_validator_bucket_root,
            recovery_proof_root,
            recovery_claim_root,
            claim_batch_root,
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
            recovery_policies: BTreeMap::new(),
            private_validator_buckets: BTreeMap::new(),
            recovery_proofs: BTreeMap::new(),
            recovery_claims: BTreeMap::new(),
            claim_batches: BTreeMap::new(),
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
        "hash_based_recovery_suite": HASH_BASED_RECOVERY_SUITE,
        "sphincs_recovery_proof_suite": SPHINCS_RECOVERY_PROOF_SUITE,
        "private_validator_bucket_suite": PRIVATE_VALIDATOR_BUCKET_SUITE,
        "low_fee_claim_batch_suite": LOW_FEE_CLAIM_BATCH_SUITE,
        "recovery_committee_attestation_suite": RECOVERY_COMMITTEE_ATTESTATION_SUITE,
        "config": state.config.public_record(),
        "counters": state.counters.public_record(),
        "roots": state.roots.public_record(),
        "recovery_policies": state
            .recovery_policies
            .values()
            .map(ValidatorBondRecoveryPolicy::public_record)
            .collect::<Vec<_>>(),
        "private_validator_buckets": state
            .private_validator_buckets
            .values()
            .map(PrivateValidatorBucket::public_record)
            .collect::<Vec<_>>(),
        "recovery_proofs": state
            .recovery_proofs
            .values()
            .map(SphincsRecoveryProof::public_record)
            .collect::<Vec<_>>(),
        "recovery_claims": state
            .recovery_claims
            .values()
            .map(RecoveryClaim::public_record)
            .collect::<Vec<_>>(),
        "claim_batches": state
            .claim_batches
            .values()
            .map(LowFeeRecoveryClaimBatch::public_record)
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
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-HASH-BASED-VALIDATOR-BOND-RECOVERY-{domain}-ID"),
        parts,
        24,
    )
}

pub fn sample_root(label: &str, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-HASH-BASED-VALIDATOR-BOND-RECOVERY-DEVNET-SAMPLE",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

pub fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-HASH-BASED-VALIDATOR-BOND-RECOVERY-{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}

pub fn record_root(domain: &str, mut values: Vec<Value>) -> String {
    values.sort_by_key(|value| value.to_string());
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-HASH-BASED-VALIDATOR-BOND-RECOVERY-{domain}"),
        &values,
    )
}
