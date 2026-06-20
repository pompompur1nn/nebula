use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialSlhDsaMlDsaEpochKeyBurnRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_ML_DSA_EPOCH_KEY_BURN_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-slh-dsa-ml-dsa-epoch-key-burn-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_ML_DSA_EPOCH_KEY_BURN_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SLH_DSA_SUITE: &str = "SLH-DSA-SHAKE-256f-epoch-key-burn-v1";
pub const ML_DSA_SUITE: &str = "ML-DSA-87-committee-rollover-v1";
pub const HYBRID_AUTH_SUITE: &str = "SLH-DSA-SHAKE-256f+ML-DSA-87-epoch-key-burn-v1";
pub const PRIVATE_RETIREMENT_BUCKET_SUITE: &str =
    "confidential-epoch-key-retirement-bucket-root-v1";
pub const LOW_FEE_BATCH_SUITE: &str = "low-fee-key-burn-proof-batching-v1";
pub const DEVNET_HEIGHT: u64 = 7_440_000;
pub const DEVNET_EPOCH: u64 = 31_000;
pub const DEVNET_SLOT: u64 = 144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_COMMITTEE_SIZE: u16 = 21;
pub const DEFAULT_ROLLOVER_THRESHOLD: u16 = 15;
pub const DEFAULT_BUCKET_MIN_KEYS: u64 = 65_536;
pub const DEFAULT_BUCKET_TARGET_KEYS: u64 = 262_144;
pub const DEFAULT_MAX_BUCKETS_PER_EPOCH: u16 = 64;
pub const DEFAULT_PROOF_BATCH_SIZE: u16 = 128;
pub const DEFAULT_MAX_PROOF_FEE_MICRO_UNITS: u64 = 650;
pub const DEFAULT_EPOCH_KEY_TTL_SLOTS: u64 = 12_960;
pub const DEFAULT_RETIREMENT_GRACE_SLOTS: u64 = 720;
pub const DEFAULT_ROLLOVER_QUORUM_BPS: u64 = 7_150;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeRole {
    EpochSigner,
    BurnWitness,
    BucketAggregator,
    RolloverCoordinator,
    FeeBatcher,
}

impl CommitteeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EpochSigner => "epoch_signer",
            Self::BurnWitness => "burn_witness",
            Self::BucketAggregator => "bucket_aggregator",
            Self::RolloverCoordinator => "rollover_coordinator",
            Self::FeeBatcher => "fee_batcher",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountKeyStatus {
    Active,
    RolloverPending,
    BurnQueued,
    BurnProved,
    Retired,
    Quarantined,
}

impl AccountKeyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::RolloverPending => "rollover_pending",
            Self::BurnQueued => "burn_queued",
            Self::BurnProved => "burn_proved",
            Self::Retired => "retired",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Collecting,
    Sealed,
    Proved,
    Anchored,
    Expired,
}

impl BucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Sealed => "sealed",
            Self::Proved => "proved",
            Self::Anchored => "anchored",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BurnProofStatus {
    Submitted,
    Batched,
    CommitteeAttested,
    Finalized,
    Rejected,
}

impl BurnProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Batched => "batched",
            Self::CommitteeAttested => "committee_attested",
            Self::Finalized => "finalized",
            Self::Rejected => "rejected",
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
    pub slh_dsa_suite: String,
    pub ml_dsa_suite: String,
    pub hybrid_auth_suite: String,
    pub private_retirement_bucket_suite: String,
    pub low_fee_batch_suite: String,
    pub min_pq_security_bits: u16,
    pub committee_size: u16,
    pub rollover_threshold: u16,
    pub bucket_min_keys: u64,
    pub bucket_target_keys: u64,
    pub max_buckets_per_epoch: u16,
    pub proof_batch_size: u16,
    pub max_proof_fee_micro_units: u64,
    pub epoch_key_ttl_slots: u64,
    pub retirement_grace_slots: u64,
    pub rollover_quorum_bps: u64,
    pub confidential_burn_required: bool,
    pub low_fee_batching_enabled: bool,
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
            slh_dsa_suite: SLH_DSA_SUITE.to_string(),
            ml_dsa_suite: ML_DSA_SUITE.to_string(),
            hybrid_auth_suite: HYBRID_AUTH_SUITE.to_string(),
            private_retirement_bucket_suite: PRIVATE_RETIREMENT_BUCKET_SUITE.to_string(),
            low_fee_batch_suite: LOW_FEE_BATCH_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            committee_size: DEFAULT_COMMITTEE_SIZE,
            rollover_threshold: DEFAULT_ROLLOVER_THRESHOLD,
            bucket_min_keys: DEFAULT_BUCKET_MIN_KEYS,
            bucket_target_keys: DEFAULT_BUCKET_TARGET_KEYS,
            max_buckets_per_epoch: DEFAULT_MAX_BUCKETS_PER_EPOCH,
            proof_batch_size: DEFAULT_PROOF_BATCH_SIZE,
            max_proof_fee_micro_units: DEFAULT_MAX_PROOF_FEE_MICRO_UNITS,
            epoch_key_ttl_slots: DEFAULT_EPOCH_KEY_TTL_SLOTS,
            retirement_grace_slots: DEFAULT_RETIREMENT_GRACE_SLOTS,
            rollover_quorum_bps: DEFAULT_ROLLOVER_QUORUM_BPS,
            confidential_burn_required: true,
            low_fee_batching_enabled: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below runtime minimum".to_string());
        }
        if self.rollover_threshold == 0 || self.rollover_threshold > self.committee_size {
            return Err("invalid committee rollover threshold".to_string());
        }
        if self.bucket_target_keys < self.bucket_min_keys {
            return Err("target retirement bucket size below minimum".to_string());
        }
        if self.max_buckets_per_epoch == 0 || self.proof_batch_size == 0 {
            return Err("epoch key burn batching limits must be positive".to_string());
        }
        if self.retirement_grace_slots > self.epoch_key_ttl_slots {
            return Err("retirement grace slots exceed epoch key ttl".to_string());
        }
        if self.rollover_quorum_bps > MAX_BPS {
            return Err("rollover quorum exceeds basis point denominator".to_string());
        }
        if !self.confidential_burn_required {
            return Err("confidential key burn must remain enabled".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub committee_members: u64,
    pub account_rollovers: u64,
    pub retirement_buckets: u64,
    pub burn_proofs: u64,
    pub proof_batches: u64,
    pub committee_attestations: u64,
    pub retired_epoch_keys: u64,
    pub quarantined_accounts: u64,
    pub total_amortized_fee_micro_units: u64,
    pub private_bucket_key_total: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub committee_member_root: String,
    pub account_rollover_root: String,
    pub retirement_bucket_root: String,
    pub burn_proof_root: String,
    pub proof_batch_root: String,
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
pub struct CommitteeMember {
    pub member_id: String,
    pub role: CommitteeRole,
    pub operator_commitment: String,
    pub slh_dsa_key_root: String,
    pub ml_dsa_key_root: String,
    pub rollover_weight_bps: u64,
    pub active: bool,
}

impl CommitteeMember {
    pub fn public_record(&self) -> Value {
        json!({
            "member_id": self.member_id,
            "role": self.role.as_str(),
            "operator_commitment": self.operator_commitment,
            "slh_dsa_key_root": self.slh_dsa_key_root,
            "ml_dsa_key_root": self.ml_dsa_key_root,
            "rollover_weight_bps": self.rollover_weight_bps,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccountRollover {
    pub account_id: String,
    pub previous_epoch: u64,
    pub next_epoch: u64,
    pub account_commitment: String,
    pub old_epoch_key_root: String,
    pub new_epoch_key_root: String,
    pub rollover_nullifier: String,
    pub status: AccountKeyStatus,
}

impl AccountRollover {
    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "previous_epoch": self.previous_epoch,
            "next_epoch": self.next_epoch,
            "account_commitment": self.account_commitment,
            "old_epoch_key_root": self.old_epoch_key_root,
            "new_epoch_key_root": self.new_epoch_key_root,
            "rollover_nullifier": self.rollover_nullifier,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateRetirementBucket {
    pub bucket_id: String,
    pub epoch: u64,
    pub encrypted_key_bucket_root: String,
    pub burn_nullifier_root: String,
    pub anonymity_set_root: String,
    pub account_commitment_root: String,
    pub key_count: u64,
    pub status: BucketStatus,
}

impl PrivateRetirementBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "epoch": self.epoch,
            "encrypted_key_bucket_root": self.encrypted_key_bucket_root,
            "burn_nullifier_root": self.burn_nullifier_root,
            "anonymity_set_root": self.anonymity_set_root,
            "account_commitment_root": self.account_commitment_root,
            "key_count": self.key_count,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BurnProof {
    pub proof_id: String,
    pub account_id: String,
    pub bucket_id: String,
    pub old_epoch_key_root: String,
    pub slh_dsa_burn_signature_root: String,
    pub ml_dsa_rollover_signature_root: String,
    pub zero_knowledge_transcript_root: String,
    pub pq_security_bits: u16,
    pub fee_micro_units: u64,
    pub status: BurnProofStatus,
}

impl BurnProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "account_id": self.account_id,
            "bucket_id": self.bucket_id,
            "old_epoch_key_root": self.old_epoch_key_root,
            "slh_dsa_burn_signature_root": self.slh_dsa_burn_signature_root,
            "ml_dsa_rollover_signature_root": self.ml_dsa_rollover_signature_root,
            "zero_knowledge_transcript_root": self.zero_knowledge_transcript_root,
            "pq_security_bits": self.pq_security_bits,
            "fee_micro_units": self.fee_micro_units,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeProofBatch {
    pub batch_id: String,
    pub epoch: u64,
    pub proof_ids: BTreeSet<String>,
    pub aggregate_fee_micro_units: u64,
    pub per_proof_fee_micro_units: u64,
    pub batch_transcript_root: String,
    pub compression_commitment_root: String,
}

impl LowFeeProofBatch {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitteeAttestation {
    pub attestation_id: String,
    pub member_id: String,
    pub batch_id: String,
    pub slh_dsa_attestation_root: String,
    pub ml_dsa_attestation_root: String,
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
    pub committee_members: BTreeMap<String, CommitteeMember>,
    pub account_rollovers: BTreeMap<String, AccountRollover>,
    pub retirement_buckets: BTreeMap<String, PrivateRetirementBucket>,
    pub burn_proofs: BTreeMap<String, BurnProof>,
    pub proof_batches: BTreeMap<String, LowFeeProofBatch>,
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
            committee_members: BTreeMap::new(),
            account_rollovers: BTreeMap::new(),
            retirement_buckets: BTreeMap::new(),
            burn_proofs: BTreeMap::new(),
            proof_batches: BTreeMap::new(),
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
        for index in 0..self.config.committee_size {
            let role = match index % 5 {
                0 => CommitteeRole::EpochSigner,
                1 => CommitteeRole::BurnWitness,
                2 => CommitteeRole::BucketAggregator,
                3 => CommitteeRole::RolloverCoordinator,
                _ => CommitteeRole::FeeBatcher,
            };
            let member_id = format!("epoch-key-burn-committee-devnet-{index:04}");
            self.committee_members.insert(
                member_id.clone(),
                CommitteeMember {
                    member_id,
                    role,
                    operator_commitment: sample_root("committee-operator", u64::from(index)),
                    slh_dsa_key_root: sample_root("committee-slh-dsa-key", u64::from(index)),
                    ml_dsa_key_root: sample_root("committee-ml-dsa-key", u64::from(index)),
                    rollover_weight_bps: self.config.rollover_quorum_bps,
                    active: true,
                },
            );
        }

        let bucket_id = deterministic_id(
            "retirement-bucket",
            &[HashPart::U64(self.epoch), HashPart::U64(0)],
        );
        self.retirement_buckets.insert(
            bucket_id.clone(),
            PrivateRetirementBucket {
                bucket_id: bucket_id.clone(),
                epoch: self.epoch,
                encrypted_key_bucket_root: sample_root("encrypted-key-bucket", 0),
                burn_nullifier_root: sample_root("burn-nullifier-set", 0),
                anonymity_set_root: sample_root("key-retirement-anonymity-set", 0),
                account_commitment_root: sample_root("retired-account-commitments", 0),
                key_count: self.config.bucket_target_keys,
                status: BucketStatus::Anchored,
            },
        );

        for index in 0_u64..3 {
            let account_id = deterministic_id(
                "account-rollover",
                &[HashPart::U64(self.epoch), HashPart::U64(index)],
            );
            let old_epoch_key_root = sample_root("old-epoch-key", index);
            self.account_rollovers.insert(
                account_id.clone(),
                AccountRollover {
                    account_id: account_id.clone(),
                    previous_epoch: self.epoch.saturating_sub(1),
                    next_epoch: self.epoch,
                    account_commitment: sample_root("account-commitment", index),
                    old_epoch_key_root: old_epoch_key_root.clone(),
                    new_epoch_key_root: sample_root("new-epoch-key", index),
                    rollover_nullifier: sample_root("rollover-nullifier", index),
                    status: AccountKeyStatus::Retired,
                },
            );

            let proof_id = deterministic_id(
                "burn-proof",
                &[HashPart::Str(&account_id), HashPart::Str(&bucket_id)],
            );
            self.burn_proofs.insert(
                proof_id.clone(),
                BurnProof {
                    proof_id,
                    account_id,
                    bucket_id: bucket_id.clone(),
                    old_epoch_key_root,
                    slh_dsa_burn_signature_root: sample_root("slh-dsa-burn-signature", index),
                    ml_dsa_rollover_signature_root: sample_root("ml-dsa-rollover-signature", index),
                    zero_knowledge_transcript_root: sample_root("zk-burn-transcript", index),
                    pq_security_bits: self.config.min_pq_security_bits,
                    fee_micro_units: 120 + index * 5,
                    status: BurnProofStatus::Finalized,
                },
            );
        }

        let proof_ids = self.burn_proofs.keys().cloned().collect::<BTreeSet<_>>();
        let batch_id = deterministic_id(
            "proof-batch",
            &[
                HashPart::U64(self.epoch),
                HashPart::U64(proof_ids.len() as u64),
            ],
        );
        self.proof_batches.insert(
            batch_id.clone(),
            LowFeeProofBatch {
                batch_id: batch_id.clone(),
                epoch: self.epoch,
                proof_ids,
                aggregate_fee_micro_units: 375,
                per_proof_fee_micro_units: 125,
                batch_transcript_root: sample_root("low-fee-proof-batch", 0),
                compression_commitment_root: sample_root("proof-compression", 0),
            },
        );

        for index in 0..self.config.rollover_threshold {
            let member_id = format!("epoch-key-burn-committee-devnet-{index:04}");
            let attestation_id = deterministic_id(
                "committee-attestation",
                &[HashPart::Str(&batch_id), HashPart::U64(u64::from(index))],
            );
            self.committee_attestations.insert(
                attestation_id.clone(),
                CommitteeAttestation {
                    attestation_id,
                    member_id,
                    batch_id: batch_id.clone(),
                    slh_dsa_attestation_root: sample_root(
                        "slh-dsa-batch-attestation",
                        u64::from(index),
                    ),
                    ml_dsa_attestation_root: sample_root(
                        "ml-dsa-batch-attestation",
                        u64::from(index),
                    ),
                    observed_state_root: sample_root(
                        "observed-state-before-finality",
                        u64::from(index),
                    ),
                    attested_slot: self.slot + 24 + u64::from(index),
                    accepted: true,
                },
            );
        }
        self.refresh();
    }

    fn refresh(&mut self) {
        self.counters = Counters {
            committee_members: self.committee_members.len() as u64,
            account_rollovers: self.account_rollovers.len() as u64,
            retirement_buckets: self.retirement_buckets.len() as u64,
            burn_proofs: self.burn_proofs.len() as u64,
            proof_batches: self.proof_batches.len() as u64,
            committee_attestations: self.committee_attestations.len() as u64,
            retired_epoch_keys: self
                .account_rollovers
                .values()
                .filter(|rollover| rollover.status == AccountKeyStatus::Retired)
                .count() as u64,
            quarantined_accounts: self
                .account_rollovers
                .values()
                .filter(|rollover| rollover.status == AccountKeyStatus::Quarantined)
                .count() as u64,
            total_amortized_fee_micro_units: self
                .burn_proofs
                .values()
                .map(|proof| proof.fee_micro_units)
                .sum(),
            private_bucket_key_total: self
                .retirement_buckets
                .values()
                .map(|bucket| bucket.key_count)
                .sum(),
        };
        self.roots = self.compute_roots();
    }

    fn compute_roots(&self) -> Roots {
        let committee_member_root = record_root(
            "committee-members",
            self.committee_members
                .values()
                .map(CommitteeMember::public_record)
                .collect(),
        );
        let account_rollover_root = record_root(
            "account-rollovers",
            self.account_rollovers
                .values()
                .map(AccountRollover::public_record)
                .collect(),
        );
        let retirement_bucket_root = record_root(
            "retirement-buckets",
            self.retirement_buckets
                .values()
                .map(PrivateRetirementBucket::public_record)
                .collect(),
        );
        let burn_proof_root = record_root(
            "burn-proofs",
            self.burn_proofs
                .values()
                .map(BurnProof::public_record)
                .collect(),
        );
        let proof_batch_root = record_root(
            "proof-batches",
            self.proof_batches
                .values()
                .map(LowFeeProofBatch::public_record)
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
                "committee_member_root": committee_member_root,
                "account_rollover_root": account_rollover_root,
                "retirement_bucket_root": retirement_bucket_root,
                "burn_proof_root": burn_proof_root,
                "proof_batch_root": proof_batch_root,
                "committee_attestation_root": committee_attestation_root,
            }),
        );
        let state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-ML-DSA-EPOCH-KEY-BURN-STATE",
            &[
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Str(&public_record_root),
                HashPart::U64(self.height),
                HashPart::U64(self.epoch),
                HashPart::U64(self.slot),
            ],
            32,
        );
        Roots {
            committee_member_root,
            account_rollover_root,
            retirement_bucket_root,
            burn_proof_root,
            proof_batch_root,
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
            committee_members: BTreeMap::new(),
            account_rollovers: BTreeMap::new(),
            retirement_buckets: BTreeMap::new(),
            burn_proofs: BTreeMap::new(),
            proof_batches: BTreeMap::new(),
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
        "slh_dsa_suite": SLH_DSA_SUITE,
        "ml_dsa_suite": ML_DSA_SUITE,
        "hybrid_auth_suite": HYBRID_AUTH_SUITE,
        "private_retirement_bucket_suite": PRIVATE_RETIREMENT_BUCKET_SUITE,
        "low_fee_batch_suite": LOW_FEE_BATCH_SUITE,
        "config": state.config.public_record(),
        "counters": state.counters.public_record(),
        "roots": state.roots.public_record(),
        "committee_members": state
            .committee_members
            .values()
            .map(CommitteeMember::public_record)
            .collect::<Vec<_>>(),
        "account_rollovers": state
            .account_rollovers
            .values()
            .map(AccountRollover::public_record)
            .collect::<Vec<_>>(),
        "retirement_buckets": state
            .retirement_buckets
            .values()
            .map(PrivateRetirementBucket::public_record)
            .collect::<Vec<_>>(),
        "burn_proofs": state
            .burn_proofs
            .values()
            .map(BurnProof::public_record)
            .collect::<Vec<_>>(),
        "proof_batches": state
            .proof_batches
            .values()
            .map(LowFeeProofBatch::public_record)
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
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-ML-DSA-EPOCH-KEY-BURN-{domain}-ID"),
        parts,
        24,
    )
}

pub fn sample_root(label: &str, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-ML-DSA-EPOCH-KEY-BURN-DEVNET-SAMPLE",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

pub fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-ML-DSA-EPOCH-KEY-BURN-{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}

pub fn record_root(domain: &str, mut values: Vec<Value>) -> String {
    values.sort_by_key(|value| value.to_string());
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-SLH-DSA-ML-DSA-EPOCH-KEY-BURN-{domain}"),
        &values,
    )
}
