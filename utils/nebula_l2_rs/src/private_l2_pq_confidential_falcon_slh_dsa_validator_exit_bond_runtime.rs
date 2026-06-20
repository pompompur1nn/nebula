use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialFalconSlhDsaValidatorExitBondRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_FALCON_SLH_DSA_VALIDATOR_EXIT_BOND_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-falcon-slh-dsa-validator-exit-bond-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_FALCON_SLH_DSA_VALIDATOR_EXIT_BOND_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const FALCON_SUITE: &str = "Falcon-1024-validator-exit-bond-envelope-v1";
pub const SLH_DSA_SUITE: &str = "SLH-DSA-SHAKE-256f-validator-exit-bond-envelope-v1";
pub const HYBRID_EXIT_AUTH_SUITE: &str =
    "Falcon-1024+SLH-DSA-SHAKE-256f-validator-exit-bond-hybrid-v1";
pub const PRIVATE_EXIT_BUCKET_SUITE: &str = "confidential-validator-exit-bucket-root-v1";
pub const ROLLOVER_BURN_EVIDENCE_SUITE: &str =
    "falcon-slh-dsa-validator-exit-rollover-burn-evidence-v1";
pub const LOW_FEE_DISPUTE_BATCH_SUITE: &str =
    "low-fee-confidential-validator-exit-dispute-batch-v1";
pub const DEVNET_HEIGHT: u64 = 8_120_000;
pub const DEVNET_EPOCH: u64 = 33_875;
pub const DEVNET_SLOT: u64 = 384;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_EXIT_BOND_ATOMIC: u64 = 25_000_000_000;
pub const DEFAULT_MIN_EXIT_DELAY_SLOTS: u64 = 2_880;
pub const DEFAULT_CHALLENGE_WINDOW_SLOTS: u64 = 720;
pub const DEFAULT_BUCKET_TARGET_EXITS: u64 = 16_384;
pub const DEFAULT_MAX_BUCKETS_PER_EPOCH: u16 = 48;
pub const DEFAULT_MAX_DISPUTE_BATCH_SIZE: u16 = 192;
pub const DEFAULT_MAX_DISPUTE_FEE_MICRO_UNITS: u64 = 425;
pub const DEFAULT_ROLLOVER_BURN_THRESHOLD: u16 = 11;
pub const DEFAULT_COMMITTEE_SIZE: u16 = 15;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitBondStatus {
    Posted,
    ExitRequested,
    Bucketed,
    Challenged,
    RolloverBurnProved,
    Released,
    Slashed,
}

impl ExitBondStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::ExitRequested => "exit_requested",
            Self::Bucketed => "bucketed",
            Self::Challenged => "challenged",
            Self::RolloverBurnProved => "rollover_burn_proved",
            Self::Released => "released",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitBucketStatus {
    Collecting,
    Sealed,
    DisputeWindowOpen,
    RolloverBurnAnchored,
    Finalized,
}

impl ExitBucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Sealed => "sealed",
            Self::DisputeWindowOpen => "dispute_window_open",
            Self::RolloverBurnAnchored => "rollover_burn_anchored",
            Self::Finalized => "finalized",
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
    pub falcon_suite: String,
    pub slh_dsa_suite: String,
    pub hybrid_exit_auth_suite: String,
    pub private_exit_bucket_suite: String,
    pub rollover_burn_evidence_suite: String,
    pub low_fee_dispute_batch_suite: String,
    pub min_pq_security_bits: u16,
    pub exit_bond_atomic: u64,
    pub min_exit_delay_slots: u64,
    pub challenge_window_slots: u64,
    pub bucket_target_exits: u64,
    pub max_buckets_per_epoch: u16,
    pub max_dispute_batch_size: u16,
    pub max_dispute_fee_micro_units: u64,
    pub committee_size: u16,
    pub rollover_burn_threshold: u16,
    pub confidential_buckets_required: bool,
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
            falcon_suite: FALCON_SUITE.to_string(),
            slh_dsa_suite: SLH_DSA_SUITE.to_string(),
            hybrid_exit_auth_suite: HYBRID_EXIT_AUTH_SUITE.to_string(),
            private_exit_bucket_suite: PRIVATE_EXIT_BUCKET_SUITE.to_string(),
            rollover_burn_evidence_suite: ROLLOVER_BURN_EVIDENCE_SUITE.to_string(),
            low_fee_dispute_batch_suite: LOW_FEE_DISPUTE_BATCH_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            exit_bond_atomic: DEFAULT_EXIT_BOND_ATOMIC,
            min_exit_delay_slots: DEFAULT_MIN_EXIT_DELAY_SLOTS,
            challenge_window_slots: DEFAULT_CHALLENGE_WINDOW_SLOTS,
            bucket_target_exits: DEFAULT_BUCKET_TARGET_EXITS,
            max_buckets_per_epoch: DEFAULT_MAX_BUCKETS_PER_EPOCH,
            max_dispute_batch_size: DEFAULT_MAX_DISPUTE_BATCH_SIZE,
            max_dispute_fee_micro_units: DEFAULT_MAX_DISPUTE_FEE_MICRO_UNITS,
            committee_size: DEFAULT_COMMITTEE_SIZE,
            rollover_burn_threshold: DEFAULT_ROLLOVER_BURN_THRESHOLD,
            confidential_buckets_required: true,
            low_fee_dispute_batching_enabled: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below validator exit bond minimum".to_string());
        }
        if self.exit_bond_atomic == 0 {
            return Err("validator exit bond must be positive".to_string());
        }
        if self.challenge_window_slots == 0
            || self.challenge_window_slots > self.min_exit_delay_slots
        {
            return Err("invalid validator exit challenge window".to_string());
        }
        if self.bucket_target_exits == 0 || self.max_buckets_per_epoch == 0 {
            return Err("private exit bucket limits must be positive".to_string());
        }
        if self.max_dispute_batch_size == 0 {
            return Err("low-fee dispute batch size must be positive".to_string());
        }
        if self.rollover_burn_threshold == 0 || self.rollover_burn_threshold > self.committee_size {
            return Err("invalid rollover burn threshold".to_string());
        }
        if !self.confidential_buckets_required {
            return Err("confidential validator exit buckets must remain enabled".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub validator_bonds: u64,
    pub private_exit_buckets: u64,
    pub rollover_burn_evidence: u64,
    pub exit_disputes: u64,
    pub dispute_batches: u64,
    pub committee_attestations: u64,
    pub released_bonds: u64,
    pub slashed_bonds: u64,
    pub total_bonded_atomic: u64,
    pub total_dispute_fee_micro_units: u64,
    pub private_bucket_exit_total: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub validator_bond_root: String,
    pub private_exit_bucket_root: String,
    pub rollover_burn_evidence_root: String,
    pub exit_dispute_root: String,
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
pub struct ValidatorExitBond {
    pub bond_id: String,
    pub validator_commitment: String,
    pub operator_commitment: String,
    pub exit_nullifier: String,
    pub bond_amount_atomic: u64,
    pub requested_epoch: u64,
    pub release_slot: u64,
    pub falcon_exit_signature_root: String,
    pub slh_dsa_exit_signature_root: String,
    pub status: ExitBondStatus,
}

impl ValidatorExitBond {
    pub fn public_record(&self) -> Value {
        json!({
            "bond_id": self.bond_id,
            "validator_commitment": self.validator_commitment,
            "operator_commitment": self.operator_commitment,
            "exit_nullifier": self.exit_nullifier,
            "bond_amount_atomic": self.bond_amount_atomic,
            "requested_epoch": self.requested_epoch,
            "release_slot": self.release_slot,
            "falcon_exit_signature_root": self.falcon_exit_signature_root,
            "slh_dsa_exit_signature_root": self.slh_dsa_exit_signature_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateExitBucket {
    pub bucket_id: String,
    pub epoch: u64,
    pub encrypted_exit_bucket_root: String,
    pub validator_commitment_root: String,
    pub exit_nullifier_root: String,
    pub bond_commitment_root: String,
    pub exit_count: u64,
    pub status: ExitBucketStatus,
}

impl PrivateExitBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "epoch": self.epoch,
            "encrypted_exit_bucket_root": self.encrypted_exit_bucket_root,
            "validator_commitment_root": self.validator_commitment_root,
            "exit_nullifier_root": self.exit_nullifier_root,
            "bond_commitment_root": self.bond_commitment_root,
            "exit_count": self.exit_count,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RolloverBurnEvidence {
    pub evidence_id: String,
    pub bond_id: String,
    pub bucket_id: String,
    pub old_validator_key_root: String,
    pub next_validator_key_root: String,
    pub falcon_rollover_signature_root: String,
    pub slh_dsa_burn_signature_root: String,
    pub zero_knowledge_transcript_root: String,
    pub pq_security_bits: u16,
    pub accepted: bool,
}

impl RolloverBurnEvidence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitDispute {
    pub dispute_id: String,
    pub bond_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub claimed_fault_root: String,
    pub fee_micro_units: u64,
    pub status: DisputeStatus,
}

impl ExitDispute {
    pub fn public_record(&self) -> Value {
        json!({
            "dispute_id": self.dispute_id,
            "bond_id": self.bond_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "claimed_fault_root": self.claimed_fault_root,
            "fee_micro_units": self.fee_micro_units,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeDisputeBatch {
    pub batch_id: String,
    pub epoch: u64,
    pub dispute_ids: BTreeSet<String>,
    pub aggregate_fee_micro_units: u64,
    pub per_dispute_fee_micro_units: u64,
    pub batch_transcript_root: String,
    pub compression_commitment_root: String,
}

impl LowFeeDisputeBatch {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitteeAttestation {
    pub attestation_id: String,
    pub committee_member_id: String,
    pub evidence_id: String,
    pub falcon_attestation_root: String,
    pub slh_dsa_attestation_root: String,
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
    pub validator_bonds: BTreeMap<String, ValidatorExitBond>,
    pub private_exit_buckets: BTreeMap<String, PrivateExitBucket>,
    pub rollover_burn_evidence: BTreeMap<String, RolloverBurnEvidence>,
    pub exit_disputes: BTreeMap<String, ExitDispute>,
    pub dispute_batches: BTreeMap<String, LowFeeDisputeBatch>,
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
            validator_bonds: BTreeMap::new(),
            private_exit_buckets: BTreeMap::new(),
            rollover_burn_evidence: BTreeMap::new(),
            exit_disputes: BTreeMap::new(),
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
            "private-exit-bucket",
            &[HashPart::U64(self.epoch), HashPart::U64(0)],
        );
        self.private_exit_buckets.insert(
            bucket_id.clone(),
            PrivateExitBucket {
                bucket_id: bucket_id.clone(),
                epoch: self.epoch,
                encrypted_exit_bucket_root: sample_root("encrypted-exit-bucket", 0),
                validator_commitment_root: sample_root("validator-commitment-set", 0),
                exit_nullifier_root: sample_root("exit-nullifier-set", 0),
                bond_commitment_root: sample_root("bond-commitment-set", 0),
                exit_count: self.config.bucket_target_exits,
                status: ExitBucketStatus::RolloverBurnAnchored,
            },
        );

        for index in 0_u64..4 {
            let bond_id = deterministic_id(
                "validator-exit-bond",
                &[HashPart::U64(self.epoch), HashPart::U64(index)],
            );
            let status = if index == 3 {
                ExitBondStatus::Slashed
            } else {
                ExitBondStatus::Released
            };
            self.validator_bonds.insert(
                bond_id.clone(),
                ValidatorExitBond {
                    bond_id: bond_id.clone(),
                    validator_commitment: sample_root("validator-commitment", index),
                    operator_commitment: sample_root("operator-commitment", index),
                    exit_nullifier: sample_root("validator-exit-nullifier", index),
                    bond_amount_atomic: self.config.exit_bond_atomic,
                    requested_epoch: self.epoch,
                    release_slot: self.slot + self.config.min_exit_delay_slots + index,
                    falcon_exit_signature_root: sample_root("falcon-exit-signature", index),
                    slh_dsa_exit_signature_root: sample_root("slh-dsa-exit-signature", index),
                    status,
                },
            );

            let evidence_id = deterministic_id(
                "rollover-burn-evidence",
                &[HashPart::Str(&bond_id), HashPart::Str(&bucket_id)],
            );
            self.rollover_burn_evidence.insert(
                evidence_id.clone(),
                RolloverBurnEvidence {
                    evidence_id,
                    bond_id: bond_id.clone(),
                    bucket_id: bucket_id.clone(),
                    old_validator_key_root: sample_root("old-validator-key", index),
                    next_validator_key_root: sample_root("next-validator-key", index),
                    falcon_rollover_signature_root: sample_root("falcon-rollover-signature", index),
                    slh_dsa_burn_signature_root: sample_root("slh-dsa-burn-signature", index),
                    zero_knowledge_transcript_root: sample_root(
                        "validator-exit-zk-transcript",
                        index,
                    ),
                    pq_security_bits: self.config.min_pq_security_bits,
                    accepted: true,
                },
            );
        }

        for index in 0_u64..2 {
            let bond_id = self
                .validator_bonds
                .keys()
                .nth(index as usize)
                .cloned()
                .unwrap_or_else(|| sample_root("missing-bond", index));
            let dispute_id = deterministic_id(
                "exit-dispute",
                &[HashPart::Str(&bond_id), HashPart::U64(index)],
            );
            self.exit_disputes.insert(
                dispute_id.clone(),
                ExitDispute {
                    dispute_id,
                    bond_id,
                    challenger_commitment: sample_root("exit-dispute-challenger", index),
                    evidence_root: sample_root("exit-dispute-evidence", index),
                    claimed_fault_root: sample_root("claimed-validator-fault", index),
                    fee_micro_units: 95 + index * 10,
                    status: DisputeStatus::Resolved,
                },
            );
        }

        let dispute_ids = self.exit_disputes.keys().cloned().collect::<BTreeSet<_>>();
        let batch_id = deterministic_id(
            "low-fee-dispute-batch",
            &[
                HashPart::U64(self.epoch),
                HashPart::U64(dispute_ids.len() as u64),
            ],
        );
        self.dispute_batches.insert(
            batch_id.clone(),
            LowFeeDisputeBatch {
                batch_id,
                epoch: self.epoch,
                dispute_ids,
                aggregate_fee_micro_units: 200,
                per_dispute_fee_micro_units: 100,
                batch_transcript_root: sample_root("low-fee-exit-dispute-batch", 0),
                compression_commitment_root: sample_root("exit-dispute-compression", 0),
            },
        );

        for index in 0..self.config.rollover_burn_threshold {
            let evidence_id = self
                .rollover_burn_evidence
                .keys()
                .next()
                .cloned()
                .unwrap_or_else(|| sample_root("missing-evidence", u64::from(index)));
            let attestation_id = deterministic_id(
                "committee-attestation",
                &[HashPart::Str(&evidence_id), HashPart::U64(u64::from(index))],
            );
            self.committee_attestations.insert(
                attestation_id.clone(),
                CommitteeAttestation {
                    attestation_id,
                    committee_member_id: format!("validator-exit-bond-committee-devnet-{index:04}"),
                    evidence_id,
                    falcon_attestation_root: sample_root(
                        "falcon-rollover-burn-attestation",
                        u64::from(index),
                    ),
                    slh_dsa_attestation_root: sample_root(
                        "slh-dsa-rollover-burn-attestation",
                        u64::from(index),
                    ),
                    observed_state_root: sample_root(
                        "validator-exit-observed-state",
                        u64::from(index),
                    ),
                    attested_slot: self.slot + 32 + u64::from(index),
                    accepted: true,
                },
            );
        }
        self.refresh();
    }

    fn refresh(&mut self) {
        self.counters = Counters {
            validator_bonds: self.validator_bonds.len() as u64,
            private_exit_buckets: self.private_exit_buckets.len() as u64,
            rollover_burn_evidence: self.rollover_burn_evidence.len() as u64,
            exit_disputes: self.exit_disputes.len() as u64,
            dispute_batches: self.dispute_batches.len() as u64,
            committee_attestations: self.committee_attestations.len() as u64,
            released_bonds: self
                .validator_bonds
                .values()
                .filter(|bond| bond.status == ExitBondStatus::Released)
                .count() as u64,
            slashed_bonds: self
                .validator_bonds
                .values()
                .filter(|bond| bond.status == ExitBondStatus::Slashed)
                .count() as u64,
            total_bonded_atomic: self
                .validator_bonds
                .values()
                .map(|bond| bond.bond_amount_atomic)
                .sum(),
            total_dispute_fee_micro_units: self
                .exit_disputes
                .values()
                .map(|dispute| dispute.fee_micro_units)
                .sum(),
            private_bucket_exit_total: self
                .private_exit_buckets
                .values()
                .map(|bucket| bucket.exit_count)
                .sum(),
        };
        self.roots = self.compute_roots();
    }

    fn compute_roots(&self) -> Roots {
        let validator_bond_root = record_root(
            "validator-bonds",
            self.validator_bonds
                .values()
                .map(ValidatorExitBond::public_record)
                .collect(),
        );
        let private_exit_bucket_root = record_root(
            "private-exit-buckets",
            self.private_exit_buckets
                .values()
                .map(PrivateExitBucket::public_record)
                .collect(),
        );
        let rollover_burn_evidence_root = record_root(
            "rollover-burn-evidence",
            self.rollover_burn_evidence
                .values()
                .map(RolloverBurnEvidence::public_record)
                .collect(),
        );
        let exit_dispute_root = record_root(
            "exit-disputes",
            self.exit_disputes
                .values()
                .map(ExitDispute::public_record)
                .collect(),
        );
        let dispute_batch_root = record_root(
            "dispute-batches",
            self.dispute_batches
                .values()
                .map(LowFeeDisputeBatch::public_record)
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
                "validator_bond_root": validator_bond_root,
                "private_exit_bucket_root": private_exit_bucket_root,
                "rollover_burn_evidence_root": rollover_burn_evidence_root,
                "exit_dispute_root": exit_dispute_root,
                "dispute_batch_root": dispute_batch_root,
                "committee_attestation_root": committee_attestation_root,
            }),
        );
        let state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-FALCON-SLH-DSA-VALIDATOR-EXIT-BOND-STATE",
            &[
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Str(&validator_bond_root),
                HashPart::Str(&private_exit_bucket_root),
                HashPart::Str(&rollover_burn_evidence_root),
                HashPart::Str(&exit_dispute_root),
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
            validator_bond_root,
            private_exit_bucket_root,
            rollover_burn_evidence_root,
            exit_dispute_root,
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
            validator_bonds: BTreeMap::new(),
            private_exit_buckets: BTreeMap::new(),
            rollover_burn_evidence: BTreeMap::new(),
            exit_disputes: BTreeMap::new(),
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
        "falcon_suite": FALCON_SUITE,
        "slh_dsa_suite": SLH_DSA_SUITE,
        "hybrid_exit_auth_suite": HYBRID_EXIT_AUTH_SUITE,
        "private_exit_bucket_suite": PRIVATE_EXIT_BUCKET_SUITE,
        "rollover_burn_evidence_suite": ROLLOVER_BURN_EVIDENCE_SUITE,
        "low_fee_dispute_batch_suite": LOW_FEE_DISPUTE_BATCH_SUITE,
        "config": state.config.public_record(),
        "counters": state.counters.public_record(),
        "roots": state.roots.public_record(),
        "validator_bonds": state
            .validator_bonds
            .values()
            .map(ValidatorExitBond::public_record)
            .collect::<Vec<_>>(),
        "private_exit_buckets": state
            .private_exit_buckets
            .values()
            .map(PrivateExitBucket::public_record)
            .collect::<Vec<_>>(),
        "rollover_burn_evidence": state
            .rollover_burn_evidence
            .values()
            .map(RolloverBurnEvidence::public_record)
            .collect::<Vec<_>>(),
        "exit_disputes": state
            .exit_disputes
            .values()
            .map(ExitDispute::public_record)
            .collect::<Vec<_>>(),
        "dispute_batches": state
            .dispute_batches
            .values()
            .map(LowFeeDisputeBatch::public_record)
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
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-FALCON-SLH-DSA-VALIDATOR-EXIT-BOND-{domain}-ID"),
        parts,
        24,
    )
}

pub fn sample_root(label: &str, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-FALCON-SLH-DSA-VALIDATOR-EXIT-BOND-DEVNET-SAMPLE",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

pub fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-FALCON-SLH-DSA-VALIDATOR-EXIT-BOND-{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}

pub fn record_root(domain: &str, mut values: Vec<Value>) -> String {
    values.sort_by_key(|value| value.to_string());
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-FALCON-SLH-DSA-VALIDATOR-EXIT-BOND-{domain}"),
        &values,
    )
}
