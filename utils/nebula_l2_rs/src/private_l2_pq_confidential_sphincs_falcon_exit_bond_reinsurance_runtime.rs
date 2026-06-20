use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialSphincsFalconExitBondReinsuranceRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_SPHINCS_FALCON_EXIT_BOND_REINSURANCE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-sphincs-falcon-exit-bond-reinsurance-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_SPHINCS_FALCON_EXIT_BOND_REINSURANCE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SPHINCS_PLUS_SUITE: &str = "SPHINCS+-SHAKE-256f-exit-bond-reinsurance-v1";
pub const FALCON_SUITE: &str = "Falcon-1024-exit-bond-reinsurance-v1";
pub const HYBRID_REINSURANCE_AUTH_SUITE: &str =
    "SPHINCS+-SHAKE-256f+Falcon-1024-exit-bond-reinsurance-hybrid-v1";
pub const PRIVATE_VALIDATOR_BUCKET_SUITE: &str =
    "confidential-validator-exit-bond-reinsurance-bucket-root-v1";
pub const BONDED_ROLLOVER_EVIDENCE_SUITE: &str = "sphincs-falcon-bonded-rollover-evidence-v1";
pub const LOW_FEE_CLAIM_BATCH_SUITE: &str =
    "low-fee-confidential-exit-bond-reinsurance-claim-batch-v1";
pub const DEVNET_HEIGHT: u64 = 8_480_000;
pub const DEVNET_EPOCH: u64 = 35_375;
pub const DEVNET_SLOT: u64 = 640;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_COMMITTEE_SIZE: u16 = 19;
pub const DEFAULT_REINSURANCE_THRESHOLD: u16 = 13;
pub const DEFAULT_EXIT_BOND_ATOMIC: u64 = 25_000_000_000;
pub const DEFAULT_REINSURED_COVERAGE_ATOMIC: u64 = 75_000_000_000;
pub const DEFAULT_PREMIUM_ATOMIC: u64 = 900_000_000;
pub const DEFAULT_BUCKET_TARGET_VALIDATORS: u64 = 24_576;
pub const DEFAULT_MAX_BUCKETS_PER_EPOCH: u16 = 44;
pub const DEFAULT_MAX_CLAIM_BATCH_SIZE: u16 = 224;
pub const DEFAULT_MAX_CLAIM_FEE_MICRO_UNITS: u64 = 325;
pub const DEFAULT_ROLLOVER_WINDOW_SLOTS: u64 = 960;
pub const DEFAULT_CLAIM_WINDOW_SLOTS: u64 = 2_880;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReinsurancePolicyStatus {
    Active,
    Bucketed,
    RolloverPending,
    EvidenceAnchored,
    Claimed,
    Released,
    Expired,
}

impl ReinsurancePolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Bucketed => "bucketed",
            Self::RolloverPending => "rollover_pending",
            Self::EvidenceAnchored => "evidence_anchored",
            Self::Claimed => "claimed",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorBucketStatus {
    Collecting,
    Sealed,
    RolloverWindowOpen,
    EvidenceAnchored,
    Finalized,
}

impl ValidatorBucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Sealed => "sealed",
            Self::RolloverWindowOpen => "rollover_window_open",
            Self::EvidenceAnchored => "evidence_anchored",
            Self::Finalized => "finalized",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloverEvidenceStatus {
    Submitted,
    CommitteeAttested,
    Accepted,
    Quarantined,
    Rejected,
}

impl RolloverEvidenceStatus {
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
    EvidenceAccepted,
    EvidenceRejected,
    Paid,
}

impl ClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Batched => "batched",
            Self::EvidenceAccepted => "evidence_accepted",
            Self::EvidenceRejected => "evidence_rejected",
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
    pub sphincs_plus_suite: String,
    pub falcon_suite: String,
    pub hybrid_reinsurance_auth_suite: String,
    pub private_validator_bucket_suite: String,
    pub bonded_rollover_evidence_suite: String,
    pub low_fee_claim_batch_suite: String,
    pub min_pq_security_bits: u16,
    pub committee_size: u16,
    pub reinsurance_threshold: u16,
    pub exit_bond_atomic: u64,
    pub reinsured_coverage_atomic: u64,
    pub premium_atomic: u64,
    pub bucket_target_validators: u64,
    pub max_buckets_per_epoch: u16,
    pub max_claim_batch_size: u16,
    pub max_claim_fee_micro_units: u64,
    pub rollover_window_slots: u64,
    pub claim_window_slots: u64,
    pub private_validator_buckets_required: bool,
    pub bonded_rollover_evidence_required: bool,
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
            sphincs_plus_suite: SPHINCS_PLUS_SUITE.to_string(),
            falcon_suite: FALCON_SUITE.to_string(),
            hybrid_reinsurance_auth_suite: HYBRID_REINSURANCE_AUTH_SUITE.to_string(),
            private_validator_bucket_suite: PRIVATE_VALIDATOR_BUCKET_SUITE.to_string(),
            bonded_rollover_evidence_suite: BONDED_ROLLOVER_EVIDENCE_SUITE.to_string(),
            low_fee_claim_batch_suite: LOW_FEE_CLAIM_BATCH_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            committee_size: DEFAULT_COMMITTEE_SIZE,
            reinsurance_threshold: DEFAULT_REINSURANCE_THRESHOLD,
            exit_bond_atomic: DEFAULT_EXIT_BOND_ATOMIC,
            reinsured_coverage_atomic: DEFAULT_REINSURED_COVERAGE_ATOMIC,
            premium_atomic: DEFAULT_PREMIUM_ATOMIC,
            bucket_target_validators: DEFAULT_BUCKET_TARGET_VALIDATORS,
            max_buckets_per_epoch: DEFAULT_MAX_BUCKETS_PER_EPOCH,
            max_claim_batch_size: DEFAULT_MAX_CLAIM_BATCH_SIZE,
            max_claim_fee_micro_units: DEFAULT_MAX_CLAIM_FEE_MICRO_UNITS,
            rollover_window_slots: DEFAULT_ROLLOVER_WINDOW_SLOTS,
            claim_window_slots: DEFAULT_CLAIM_WINDOW_SLOTS,
            private_validator_buckets_required: true,
            bonded_rollover_evidence_required: true,
            low_fee_claim_batching_enabled: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below exit bond reinsurance minimum".to_string());
        }
        if self.reinsurance_threshold == 0 || self.reinsurance_threshold > self.committee_size {
            return Err("invalid exit bond reinsurance threshold".to_string());
        }
        if self.exit_bond_atomic == 0
            || self.premium_atomic == 0
            || self.reinsured_coverage_atomic <= self.exit_bond_atomic
        {
            return Err("invalid exit bond reinsurance economics".to_string());
        }
        if self.bucket_target_validators == 0 || self.max_buckets_per_epoch == 0 {
            return Err("private validator bucket limits must be positive".to_string());
        }
        if self.max_claim_batch_size == 0 {
            return Err("low-fee reinsurance claim batch size must be positive".to_string());
        }
        if self.rollover_window_slots == 0 || self.rollover_window_slots > self.claim_window_slots {
            return Err("invalid bonded rollover evidence window".to_string());
        }
        if !self.private_validator_buckets_required {
            return Err("private validator buckets must remain enabled".to_string());
        }
        if !self.bonded_rollover_evidence_required {
            return Err("bonded rollover evidence must remain enabled".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub reinsurance_policies: u64,
    pub private_validator_buckets: u64,
    pub bonded_rollover_evidence: u64,
    pub reinsurance_claims: u64,
    pub claim_batches: u64,
    pub committee_attestations: u64,
    pub active_policies: u64,
    pub claimed_policies: u64,
    pub released_policies: u64,
    pub total_exit_bond_atomic: u64,
    pub total_reinsured_coverage_atomic: u64,
    pub total_premium_atomic: u64,
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
    pub reinsurance_policy_root: String,
    pub private_validator_bucket_root: String,
    pub bonded_rollover_evidence_root: String,
    pub reinsurance_claim_root: String,
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
pub struct ExitBondReinsurancePolicy {
    pub policy_id: String,
    pub validator_commitment: String,
    pub operator_commitment: String,
    pub exit_bond_commitment: String,
    pub rollover_nullifier: String,
    pub premium_atomic: u64,
    pub exit_bond_atomic: u64,
    pub reinsured_coverage_atomic: u64,
    pub effective_epoch: u64,
    pub expires_epoch: u64,
    pub sphincs_policy_signature_root: String,
    pub falcon_policy_signature_root: String,
    pub status: ReinsurancePolicyStatus,
}

impl ExitBondReinsurancePolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "validator_commitment": self.validator_commitment,
            "operator_commitment": self.operator_commitment,
            "exit_bond_commitment": self.exit_bond_commitment,
            "rollover_nullifier": self.rollover_nullifier,
            "premium_atomic": self.premium_atomic,
            "exit_bond_atomic": self.exit_bond_atomic,
            "reinsured_coverage_atomic": self.reinsured_coverage_atomic,
            "effective_epoch": self.effective_epoch,
            "expires_epoch": self.expires_epoch,
            "sphincs_policy_signature_root": self.sphincs_policy_signature_root,
            "falcon_policy_signature_root": self.falcon_policy_signature_root,
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
    pub exit_bond_commitment_root: String,
    pub rollover_nullifier_root: String,
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
            "exit_bond_commitment_root": self.exit_bond_commitment_root,
            "rollover_nullifier_root": self.rollover_nullifier_root,
            "policy_commitment_root": self.policy_commitment_root,
            "validator_count": self.validator_count,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BondedRolloverEvidence {
    pub evidence_id: String,
    pub policy_id: String,
    pub bucket_id: String,
    pub old_exit_bond_root: String,
    pub next_exit_bond_root: String,
    pub rollover_bond_commitment_root: String,
    pub sphincs_rollover_signature_root: String,
    pub falcon_reinsurance_signature_root: String,
    pub zero_knowledge_transcript_root: String,
    pub pq_security_bits: u16,
    pub rollover_slot: u64,
    pub status: RolloverEvidenceStatus,
}

impl BondedRolloverEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "policy_id": self.policy_id,
            "bucket_id": self.bucket_id,
            "old_exit_bond_root": self.old_exit_bond_root,
            "next_exit_bond_root": self.next_exit_bond_root,
            "rollover_bond_commitment_root": self.rollover_bond_commitment_root,
            "sphincs_rollover_signature_root": self.sphincs_rollover_signature_root,
            "falcon_reinsurance_signature_root": self.falcon_reinsurance_signature_root,
            "zero_knowledge_transcript_root": self.zero_knowledge_transcript_root,
            "pq_security_bits": self.pq_security_bits,
            "rollover_slot": self.rollover_slot,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReinsuranceClaim {
    pub claim_id: String,
    pub policy_id: String,
    pub claimant_commitment: String,
    pub evidence_root: String,
    pub loss_event_root: String,
    pub payout_atomic: u64,
    pub fee_micro_units: u64,
    pub status: ClaimStatus,
}

impl ReinsuranceClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "policy_id": self.policy_id,
            "claimant_commitment": self.claimant_commitment,
            "evidence_root": self.evidence_root,
            "loss_event_root": self.loss_event_root,
            "payout_atomic": self.payout_atomic,
            "fee_micro_units": self.fee_micro_units,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeReinsuranceClaimBatch {
    pub batch_id: String,
    pub epoch: u64,
    pub claim_ids: BTreeSet<String>,
    pub aggregate_fee_micro_units: u64,
    pub per_claim_fee_micro_units: u64,
    pub batch_transcript_root: String,
    pub compression_commitment_root: String,
}

impl LowFeeReinsuranceClaimBatch {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitteeAttestation {
    pub attestation_id: String,
    pub committee_member_id: String,
    pub evidence_id: String,
    pub sphincs_attestation_root: String,
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
    pub reinsurance_policies: BTreeMap<String, ExitBondReinsurancePolicy>,
    pub private_validator_buckets: BTreeMap<String, PrivateValidatorBucket>,
    pub bonded_rollover_evidence: BTreeMap<String, BondedRolloverEvidence>,
    pub reinsurance_claims: BTreeMap<String, ReinsuranceClaim>,
    pub claim_batches: BTreeMap<String, LowFeeReinsuranceClaimBatch>,
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
            reinsurance_policies: BTreeMap::new(),
            private_validator_buckets: BTreeMap::new(),
            bonded_rollover_evidence: BTreeMap::new(),
            reinsurance_claims: BTreeMap::new(),
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
                exit_bond_commitment_root: sample_root("exit-bond-commitment-set", 0),
                rollover_nullifier_root: sample_root("reinsurance-rollover-nullifier-set", 0),
                policy_commitment_root: sample_root("reinsurance-policy-commitment-set", 0),
                validator_count: self.config.bucket_target_validators,
                status: ValidatorBucketStatus::EvidenceAnchored,
            },
        );

        for index in 0_u64..4 {
            let policy_id = deterministic_id(
                "reinsurance-policy",
                &[HashPart::U64(self.epoch), HashPart::U64(index)],
            );
            let status = match index {
                0 | 1 => ReinsurancePolicyStatus::EvidenceAnchored,
                2 => ReinsurancePolicyStatus::Claimed,
                _ => ReinsurancePolicyStatus::Active,
            };
            self.reinsurance_policies.insert(
                policy_id.clone(),
                ExitBondReinsurancePolicy {
                    policy_id: policy_id.clone(),
                    validator_commitment: sample_root("reinsured-validator-commitment", index),
                    operator_commitment: sample_root("reinsurance-operator-commitment", index),
                    exit_bond_commitment: sample_root("reinsured-exit-bond", index),
                    rollover_nullifier: sample_root("exit-bond-rollover-nullifier", index),
                    premium_atomic: self.config.premium_atomic,
                    exit_bond_atomic: self.config.exit_bond_atomic,
                    reinsured_coverage_atomic: self.config.reinsured_coverage_atomic,
                    effective_epoch: self.epoch,
                    expires_epoch: self.epoch + 12,
                    sphincs_policy_signature_root: sample_root("sphincs-policy-signature", index),
                    falcon_policy_signature_root: sample_root("falcon-policy-signature", index),
                    status,
                },
            );

            let evidence_id = deterministic_id(
                "bonded-rollover-evidence",
                &[HashPart::Str(&policy_id), HashPart::Str(&bucket_id)],
            );
            self.bonded_rollover_evidence.insert(
                evidence_id.clone(),
                BondedRolloverEvidence {
                    evidence_id,
                    policy_id: policy_id.clone(),
                    bucket_id: bucket_id.clone(),
                    old_exit_bond_root: sample_root("old-exit-bond", index),
                    next_exit_bond_root: sample_root("next-exit-bond", index),
                    rollover_bond_commitment_root: sample_root("rollover-bond-commitment", index),
                    sphincs_rollover_signature_root: sample_root(
                        "sphincs-rollover-signature",
                        index,
                    ),
                    falcon_reinsurance_signature_root: sample_root(
                        "falcon-reinsurance-signature",
                        index,
                    ),
                    zero_knowledge_transcript_root: sample_root(
                        "exit-bond-reinsurance-zk-transcript",
                        index,
                    ),
                    pq_security_bits: self.config.min_pq_security_bits,
                    rollover_slot: self.slot + index * 12,
                    status: RolloverEvidenceStatus::Accepted,
                },
            );
        }

        for index in 0_u64..2 {
            let policy_id = self
                .reinsurance_policies
                .keys()
                .nth(index as usize)
                .cloned()
                .unwrap_or_else(|| sample_root("missing-policy", index));
            let claim_id = deterministic_id(
                "reinsurance-claim",
                &[HashPart::Str(&policy_id), HashPart::U64(index)],
            );
            self.reinsurance_claims.insert(
                claim_id.clone(),
                ReinsuranceClaim {
                    claim_id,
                    policy_id,
                    claimant_commitment: sample_root("reinsurance-claimant", index),
                    evidence_root: sample_root("reinsurance-claim-evidence", index),
                    loss_event_root: sample_root("exit-bond-loss-event", index),
                    payout_atomic: self.config.reinsured_coverage_atomic / 2,
                    fee_micro_units: 70 + index * 20,
                    status: ClaimStatus::Paid,
                },
            );
        }

        let claim_ids = self
            .reinsurance_claims
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
            LowFeeReinsuranceClaimBatch {
                batch_id,
                epoch: self.epoch,
                claim_ids,
                aggregate_fee_micro_units: 150,
                per_claim_fee_micro_units: 75,
                batch_transcript_root: sample_root("low-fee-reinsurance-claim-batch", 0),
                compression_commitment_root: sample_root("reinsurance-claim-compression", 0),
            },
        );

        for index in 0..self.config.reinsurance_threshold {
            let evidence_id = self
                .bonded_rollover_evidence
                .keys()
                .next()
                .cloned()
                .unwrap_or_else(|| sample_root("missing-rollover-evidence", u64::from(index)));
            let attestation_id = deterministic_id(
                "committee-attestation",
                &[HashPart::Str(&evidence_id), HashPart::U64(u64::from(index))],
            );
            self.committee_attestations.insert(
                attestation_id.clone(),
                CommitteeAttestation {
                    attestation_id,
                    committee_member_id: format!(
                        "exit-bond-reinsurance-committee-devnet-{index:04}"
                    ),
                    evidence_id,
                    sphincs_attestation_root: sample_root(
                        "sphincs-reinsurance-attestation",
                        u64::from(index),
                    ),
                    falcon_attestation_root: sample_root(
                        "falcon-reinsurance-attestation",
                        u64::from(index),
                    ),
                    observed_state_root: sample_root(
                        "exit-bond-reinsurance-observed-state",
                        u64::from(index),
                    ),
                    attested_slot: self.slot + 56 + u64::from(index),
                    accepted: true,
                },
            );
        }
        self.refresh();
    }

    fn refresh(&mut self) {
        self.counters = Counters {
            reinsurance_policies: self.reinsurance_policies.len() as u64,
            private_validator_buckets: self.private_validator_buckets.len() as u64,
            bonded_rollover_evidence: self.bonded_rollover_evidence.len() as u64,
            reinsurance_claims: self.reinsurance_claims.len() as u64,
            claim_batches: self.claim_batches.len() as u64,
            committee_attestations: self.committee_attestations.len() as u64,
            active_policies: self
                .reinsurance_policies
                .values()
                .filter(|policy| policy.status == ReinsurancePolicyStatus::Active)
                .count() as u64,
            claimed_policies: self
                .reinsurance_policies
                .values()
                .filter(|policy| policy.status == ReinsurancePolicyStatus::Claimed)
                .count() as u64,
            released_policies: self
                .reinsurance_policies
                .values()
                .filter(|policy| policy.status == ReinsurancePolicyStatus::Released)
                .count() as u64,
            total_exit_bond_atomic: self
                .reinsurance_policies
                .values()
                .map(|policy| policy.exit_bond_atomic)
                .sum(),
            total_reinsured_coverage_atomic: self
                .reinsurance_policies
                .values()
                .map(|policy| policy.reinsured_coverage_atomic)
                .sum(),
            total_premium_atomic: self
                .reinsurance_policies
                .values()
                .map(|policy| policy.premium_atomic)
                .sum(),
            total_claim_fee_micro_units: self
                .reinsurance_claims
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
        let reinsurance_policy_root = record_root(
            "reinsurance-policies",
            self.reinsurance_policies
                .values()
                .map(ExitBondReinsurancePolicy::public_record)
                .collect(),
        );
        let private_validator_bucket_root = record_root(
            "private-validator-buckets",
            self.private_validator_buckets
                .values()
                .map(PrivateValidatorBucket::public_record)
                .collect(),
        );
        let bonded_rollover_evidence_root = record_root(
            "bonded-rollover-evidence",
            self.bonded_rollover_evidence
                .values()
                .map(BondedRolloverEvidence::public_record)
                .collect(),
        );
        let reinsurance_claim_root = record_root(
            "reinsurance-claims",
            self.reinsurance_claims
                .values()
                .map(ReinsuranceClaim::public_record)
                .collect(),
        );
        let claim_batch_root = record_root(
            "claim-batches",
            self.claim_batches
                .values()
                .map(LowFeeReinsuranceClaimBatch::public_record)
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
                "reinsurance_policy_root": reinsurance_policy_root,
                "private_validator_bucket_root": private_validator_bucket_root,
                "bonded_rollover_evidence_root": bonded_rollover_evidence_root,
                "reinsurance_claim_root": reinsurance_claim_root,
                "claim_batch_root": claim_batch_root,
                "committee_attestation_root": committee_attestation_root,
            }),
        );
        let state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SPHINCS-FALCON-EXIT-BOND-REINSURANCE-STATE",
            &[
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Str(&reinsurance_policy_root),
                HashPart::Str(&private_validator_bucket_root),
                HashPart::Str(&bonded_rollover_evidence_root),
                HashPart::Str(&reinsurance_claim_root),
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
            reinsurance_policy_root,
            private_validator_bucket_root,
            bonded_rollover_evidence_root,
            reinsurance_claim_root,
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
            reinsurance_policies: BTreeMap::new(),
            private_validator_buckets: BTreeMap::new(),
            bonded_rollover_evidence: BTreeMap::new(),
            reinsurance_claims: BTreeMap::new(),
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
        "sphincs_plus_suite": SPHINCS_PLUS_SUITE,
        "falcon_suite": FALCON_SUITE,
        "hybrid_reinsurance_auth_suite": HYBRID_REINSURANCE_AUTH_SUITE,
        "private_validator_bucket_suite": PRIVATE_VALIDATOR_BUCKET_SUITE,
        "bonded_rollover_evidence_suite": BONDED_ROLLOVER_EVIDENCE_SUITE,
        "low_fee_claim_batch_suite": LOW_FEE_CLAIM_BATCH_SUITE,
        "config": state.config.public_record(),
        "counters": state.counters.public_record(),
        "roots": state.roots.public_record(),
        "reinsurance_policies": state
            .reinsurance_policies
            .values()
            .map(ExitBondReinsurancePolicy::public_record)
            .collect::<Vec<_>>(),
        "private_validator_buckets": state
            .private_validator_buckets
            .values()
            .map(PrivateValidatorBucket::public_record)
            .collect::<Vec<_>>(),
        "bonded_rollover_evidence": state
            .bonded_rollover_evidence
            .values()
            .map(BondedRolloverEvidence::public_record)
            .collect::<Vec<_>>(),
        "reinsurance_claims": state
            .reinsurance_claims
            .values()
            .map(ReinsuranceClaim::public_record)
            .collect::<Vec<_>>(),
        "claim_batches": state
            .claim_batches
            .values()
            .map(LowFeeReinsuranceClaimBatch::public_record)
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
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-SPHINCS-FALCON-EXIT-BOND-REINSURANCE-{domain}-ID"),
        parts,
        24,
    )
}

pub fn sample_root(label: &str, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SPHINCS-FALCON-EXIT-BOND-REINSURANCE-DEVNET-SAMPLE",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

pub fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-SPHINCS-FALCON-EXIT-BOND-REINSURANCE-{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}

pub fn record_root(domain: &str, mut values: Vec<Value>) -> String {
    values.sort_by_key(|value| value.to_string());
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-SPHINCS-FALCON-EXIT-BOND-REINSURANCE-{domain}"),
        &values,
    )
}
