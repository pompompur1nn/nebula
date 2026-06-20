use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialQuantumRandomBeaconCommitteeRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_QUANTUM_RANDOM_BEACON_COMMITTEE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-quantum-random-beacon-committee-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_QUANTUM_RANDOM_BEACON_COMMITTEE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const BEACON_SUITE: &str = "confidential-quantum-randomness-transcript-v1";
pub const PQ_COMMITTEE_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-beacon-v1";
pub const SEALED_SHARE_SUITE: &str = "pq-sealed-entropy-share-commitment-root-v1";
pub const BIAS_AUDIT_SUITE: &str = "fairness-bias-audit-public-summary-root-v1";
pub const PRIVACY_REDACTION_SUITE: &str =
    "roots-only-confidential-random-beacon-redaction-budget-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "low-fee-beacon-participation-rebate-root-v1";
pub const DEVNET_HEIGHT: u64 = 1_248_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_EPOCH_LENGTH_BLOCKS: u64 = 120;
pub const DEFAULT_REVEAL_WINDOW_BLOCKS: u64 = 18;
pub const DEFAULT_QUARANTINE_BLOCKS: u64 = 720;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_COMMITTEE_SIZE: usize = 5;
pub const DEFAULT_MAX_COMMITTEE_SIZE: usize = 128;
pub const DEFAULT_THRESHOLD_BPS: u64 = 6_700;
pub const DEFAULT_MAX_BIAS_SCORE_BPS: u64 = 125;
pub const DEFAULT_LOW_FEE_LIMIT_MICRONERO: u64 = 1_200;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_PRIVACY_REDACTION_BUDGET: u64 = 96;
pub const DEFAULT_TRANSCRIPT_RETENTION_EPOCHS: u64 = 4_096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeRole {
    EntropyDealer,
    ShareSealer,
    RevealVerifier,
    BiasAuditor,
    RebateSponsor,
    EmergencyObserver,
}

impl CommitteeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EntropyDealer => "entropy_dealer",
            Self::ShareSealer => "share_sealer",
            Self::RevealVerifier => "reveal_verifier",
            Self::BiasAuditor => "bias_auditor",
            Self::RebateSponsor => "rebate_sponsor",
            Self::EmergencyObserver => "emergency_observer",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAlgorithm {
    MlKem1024MlDsa87,
    SlhDsaShake256f,
    Falcon1024Hybrid,
    Dilithium5Hybrid,
}

impl PqAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlKem1024MlDsa87 => "ml_kem_1024_ml_dsa_87",
            Self::SlhDsaShake256f => "slh_dsa_shake_256f",
            Self::Falcon1024Hybrid => "falcon_1024_hybrid",
            Self::Dilithium5Hybrid => "dilithium_5_hybrid",
        }
    }

    pub fn security_bits(self) -> u16 {
        match self {
            Self::MlKem1024MlDsa87 | Self::SlhDsaShake256f => 256,
            Self::Falcon1024Hybrid | Self::Dilithium5Hybrid => 192,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochStatus {
    Scheduled,
    Sealing,
    Revealing,
    Finalized,
    Audited,
    Quarantined,
}

impl EpochStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Sealing => "sealing",
            Self::Revealing => "revealing",
            Self::Finalized => "finalized",
            Self::Audited => "audited",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn accepts_shares(self) -> bool {
        matches!(self, Self::Scheduled | Self::Sealing)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareStatus {
    Sealed,
    Revealed,
    Included,
    Stale,
    Quarantined,
    Rejected,
}

impl ShareStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Revealed => "revealed",
            Self::Included => "included",
            Self::Stale => "stale",
            Self::Quarantined => "quarantined",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Reserved,
    Earned,
    Settled,
    Expired,
    Revoked,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Earned => "earned",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub monero_network: String,
    pub l2_network: String,
    pub activation_height: u64,
    pub epoch_length_blocks: u64,
    pub reveal_window_blocks: u64,
    pub quarantine_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_committee_size: usize,
    pub max_committee_size: usize,
    pub threshold_bps: u64,
    pub max_bias_score_bps: u64,
    pub low_fee_limit_micronero: u64,
    pub rebate_ttl_blocks: u64,
    pub privacy_redaction_budget: u64,
    pub transcript_retention_epochs: u64,
    pub allowed_algorithms: BTreeSet<PqAlgorithm>,
    pub require_confidential_shares: bool,
    pub require_bias_audits: bool,
    pub allow_low_fee_rebates: bool,
    pub deterministic_roots: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            monero_network: "monero-devnet".to_string(),
            l2_network: "nebula-private-l2-devnet".to_string(),
            activation_height: DEVNET_HEIGHT,
            epoch_length_blocks: DEFAULT_EPOCH_LENGTH_BLOCKS,
            reveal_window_blocks: DEFAULT_REVEAL_WINDOW_BLOCKS,
            quarantine_blocks: DEFAULT_QUARANTINE_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_committee_size: DEFAULT_MIN_COMMITTEE_SIZE,
            max_committee_size: DEFAULT_MAX_COMMITTEE_SIZE,
            threshold_bps: DEFAULT_THRESHOLD_BPS,
            max_bias_score_bps: DEFAULT_MAX_BIAS_SCORE_BPS,
            low_fee_limit_micronero: DEFAULT_LOW_FEE_LIMIT_MICRONERO,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            privacy_redaction_budget: DEFAULT_PRIVACY_REDACTION_BUDGET,
            transcript_retention_epochs: DEFAULT_TRANSCRIPT_RETENTION_EPOCHS,
            allowed_algorithms: BTreeSet::from([
                PqAlgorithm::MlKem1024MlDsa87,
                PqAlgorithm::SlhDsaShake256f,
            ]),
            require_confidential_shares: true,
            require_bias_audits: true,
            allow_low_fee_rebates: true,
            deterministic_roots: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "beacon_suite": BEACON_SUITE,
            "pq_committee_suite": PQ_COMMITTEE_SUITE,
            "sealed_share_suite": SEALED_SHARE_SUITE,
            "bias_audit_suite": BIAS_AUDIT_SUITE,
            "privacy_redaction_suite": PRIVACY_REDACTION_SUITE,
            "low_fee_rebate_suite": LOW_FEE_REBATE_SUITE,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "activation_height": self.activation_height,
            "epoch_length_blocks": self.epoch_length_blocks,
            "reveal_window_blocks": self.reveal_window_blocks,
            "quarantine_blocks": self.quarantine_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_committee_size": self.min_committee_size,
            "max_committee_size": self.max_committee_size,
            "threshold_bps": self.threshold_bps,
            "max_bias_score_bps": self.max_bias_score_bps,
            "low_fee_limit_micronero": self.low_fee_limit_micronero,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "privacy_redaction_budget": self.privacy_redaction_budget,
            "transcript_retention_epochs": self.transcript_retention_epochs,
            "allowed_algorithms": self.allowed_algorithms,
            "require_confidential_shares": self.require_confidential_shares,
            "require_bias_audits": self.require_bias_audits,
            "allow_low_fee_rebates": self.allow_low_fee_rebates,
            "deterministic_roots": self.deterministic_roots,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub epochs: u64,
    pub committee_members: u64,
    pub sealed_shares: u64,
    pub revealed_shares: u64,
    pub transcripts: u64,
    pub bias_audits: u64,
    pub stale_share_quarantines: u64,
    pub low_fee_rebates: u64,
    pub privacy_redaction_budgets: u64,
    pub fixture_records: u64,
    pub total_entropy_bits: u128,
    pub total_rebate_micronero: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub epoch_root: String,
    pub committee_member_root: String,
    pub sealed_share_root: String,
    pub randomness_transcript_root: String,
    pub bias_audit_root: String,
    pub stale_share_quarantine_root: String,
    pub low_fee_rebate_root: String,
    pub privacy_redaction_budget_root: String,
    pub fixture_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BeaconEpochRecord {
    pub epoch_id: String,
    pub epoch_index: u64,
    pub start_height: u64,
    pub seal_deadline_height: u64,
    pub reveal_deadline_height: u64,
    pub committee_root: String,
    pub seed_commitment_root: String,
    pub min_reveals: u64,
    pub status: EpochStatus,
    pub randomness_root: Option<String>,
    pub transcript_id: Option<String>,
    pub fairness_anchor_root: String,
}

impl BeaconEpochRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "epoch_id": self.epoch_id,
            "epoch_index": self.epoch_index,
            "start_height": self.start_height,
            "seal_deadline_height": self.seal_deadline_height,
            "reveal_deadline_height": self.reveal_deadline_height,
            "committee_root": self.committee_root,
            "seed_commitment_root": self.seed_commitment_root,
            "min_reveals": self.min_reveals,
            "status": self.status,
            "randomness_root": self.randomness_root,
            "transcript_id": self.transcript_id,
            "fairness_anchor_root": self.fairness_anchor_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqCommitteeMemberRecord {
    pub member_id: String,
    pub operator_commitment: String,
    pub pq_key_commitment: String,
    pub algorithm: PqAlgorithm,
    pub roles: BTreeSet<CommitteeRole>,
    pub stake_commitment: String,
    pub privacy_group_root: String,
    pub availability_score_bps: u64,
    pub fairness_weight: u64,
    pub active_from_epoch: u64,
    pub active_until_epoch: Option<u64>,
    pub quarantined_until_height: Option<u64>,
}

impl PqCommitteeMemberRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "member_id": self.member_id,
            "operator_commitment": self.operator_commitment,
            "pq_key_commitment": self.pq_key_commitment,
            "algorithm": self.algorithm,
            "roles": self.roles,
            "stake_commitment": self.stake_commitment,
            "privacy_group_root": self.privacy_group_root,
            "availability_score_bps": self.availability_score_bps,
            "fairness_weight": self.fairness_weight,
            "active_from_epoch": self.active_from_epoch,
            "active_until_epoch": self.active_until_epoch,
            "quarantined_until_height": self.quarantined_until_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealedEntropyShareRecord {
    pub share_id: String,
    pub epoch_id: String,
    pub member_id: String,
    pub sealed_entropy_commitment: String,
    pub ciphertext_root: String,
    pub pq_proof_root: String,
    pub submitted_height: u64,
    pub reveal_height: Option<u64>,
    pub status: ShareStatus,
    pub entropy_bits: u64,
    pub redaction_budget_id: Option<String>,
}

impl SealedEntropyShareRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "share_id": self.share_id,
            "epoch_id": self.epoch_id,
            "member_id": self.member_id,
            "sealed_entropy_commitment": self.sealed_entropy_commitment,
            "ciphertext_root": self.ciphertext_root,
            "pq_proof_root": self.pq_proof_root,
            "submitted_height": self.submitted_height,
            "reveal_height": self.reveal_height,
            "status": self.status,
            "entropy_bits": self.entropy_bits,
            "redaction_budget_id": self.redaction_budget_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RandomnessTranscriptRecord {
    pub transcript_id: String,
    pub epoch_id: String,
    pub included_share_root: String,
    pub excluded_share_root: String,
    pub reveal_order_root: String,
    pub randomness_output_root: String,
    pub deterministic_mix_root: String,
    pub verifier_attestation_root: String,
    pub finalized_height: u64,
    pub included_shares: u64,
}

impl RandomnessTranscriptRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BiasAuditRecord {
    pub audit_id: String,
    pub epoch_id: String,
    pub transcript_id: String,
    pub auditor_commitment: String,
    pub sample_window_root: String,
    pub bias_score_bps: u64,
    pub max_bias_score_bps: u64,
    pub passed: bool,
    pub public_summary_root: String,
}

impl BiasAuditRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StaleShareQuarantineRecord {
    pub quarantine_id: String,
    pub share_id: String,
    pub member_id: String,
    pub epoch_id: String,
    pub reason_code: String,
    pub evidence_root: String,
    pub quarantine_until_height: u64,
    pub rebate_revoked: bool,
}

impl StaleShareQuarantineRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeBeaconRebateRecord {
    pub rebate_id: String,
    pub epoch_id: String,
    pub member_id: String,
    pub fee_commitment: String,
    pub rebate_commitment: String,
    pub max_fee_micronero: u64,
    pub expires_at_height: u64,
    pub status: RebateStatus,
}

impl LowFeeBeaconRebateRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyRedactionBudgetRecord {
    pub budget_id: String,
    pub owner_commitment: String,
    pub epoch_id: Option<String>,
    pub budget_units: u64,
    pub spent_units: u64,
    pub redaction_policy_root: String,
    pub nullifier_root: String,
}

impl PrivacyRedactionBudgetRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FixtureRecord {
    pub fixture_id: String,
    pub label: String,
    pub fixture_root: String,
    pub deterministic_seed_root: String,
    pub notes_root: String,
}

impl FixtureRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CommitteeMemberRequest {
    pub operator_commitment: String,
    pub pq_key_commitment: String,
    pub algorithm: PqAlgorithm,
    pub roles: BTreeSet<CommitteeRole>,
    pub stake_commitment: String,
    pub privacy_group_root: String,
    pub availability_score_bps: u64,
    pub fairness_weight: u64,
    pub active_from_epoch: u64,
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BeaconEpochRequest {
    pub epoch_index: u64,
    pub start_height: u64,
    pub committee_member_ids: Vec<String>,
    pub seed_commitment_root: String,
    pub fairness_anchor_root: String,
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealedEntropyShareRequest {
    pub epoch_id: String,
    pub member_id: String,
    pub sealed_entropy_commitment: String,
    pub ciphertext_root: String,
    pub pq_proof_root: String,
    pub submitted_height: u64,
    pub entropy_bits: u64,
    pub redaction_budget_id: Option<String>,
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSafeSummary {
    pub state_root: String,
    pub active_epochs: u64,
    pub active_members: u64,
    pub sealed_shares: u64,
    pub finalized_transcripts: u64,
    pub quarantined_shares: u64,
    pub total_rebate_micronero: u128,
    pub pq_security_floor_bits: u16,
    pub public_record_root: String,
}

impl OperatorSafeSummary {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub epochs: BTreeMap<String, BeaconEpochRecord>,
    pub committee_members: BTreeMap<String, PqCommitteeMemberRecord>,
    pub sealed_shares: BTreeMap<String, SealedEntropyShareRecord>,
    pub randomness_transcripts: BTreeMap<String, RandomnessTranscriptRecord>,
    pub bias_audits: BTreeMap<String, BiasAuditRecord>,
    pub stale_share_quarantines: BTreeMap<String, StaleShareQuarantineRecord>,
    pub low_fee_rebates: BTreeMap<String, LowFeeBeaconRebateRecord>,
    pub privacy_redaction_budgets: BTreeMap<String, PrivacyRedactionBudgetRecord>,
    pub fixtures: BTreeMap<String, FixtureRecord>,
    pub public_records: BTreeMap<String, Value>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::default(),
            epochs: BTreeMap::new(),
            committee_members: BTreeMap::new(),
            sealed_shares: BTreeMap::new(),
            randomness_transcripts: BTreeMap::new(),
            bias_audits: BTreeMap::new(),
            stale_share_quarantines: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            privacy_redaction_budgets: BTreeMap::new(),
            fixtures: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            ..Self::default()
        };
        state.refresh_roots();
        state
    }

    pub fn register_committee_member(
        &mut self,
        request: CommitteeMemberRequest,
    ) -> PrivateL2PqConfidentialQuantumRandomBeaconCommitteeRuntimeResult<String> {
        require_algorithm(&self.config, request.algorithm)?;
        require(
            request.algorithm.security_bits() >= self.config.min_pq_security_bits,
            "committee member algorithm is below the configured PQ security floor",
        )?;
        require(
            request.availability_score_bps <= MAX_BPS,
            "availability score exceeds basis point maximum",
        )?;
        require(
            request.fairness_weight > 0,
            "fairness weight must be non-zero",
        )?;

        let member_id = id_from_record(
            "PRIVATE-L2-PQ-QRB-COMMITTEE-MEMBER-ID",
            &json!({
                "operator_commitment": request.operator_commitment,
                "pq_key_commitment": request.pq_key_commitment,
                "algorithm": request.algorithm,
                "active_from_epoch": request.active_from_epoch,
                "nonce": request.nonce,
            }),
        );
        let record = PqCommitteeMemberRecord {
            member_id: member_id.clone(),
            operator_commitment: request.operator_commitment,
            pq_key_commitment: request.pq_key_commitment,
            algorithm: request.algorithm,
            roles: request.roles,
            stake_commitment: request.stake_commitment,
            privacy_group_root: request.privacy_group_root,
            availability_score_bps: request.availability_score_bps,
            fairness_weight: request.fairness_weight,
            active_from_epoch: request.active_from_epoch,
            active_until_epoch: None,
            quarantined_until_height: None,
        };
        self.committee_members.insert(member_id.clone(), record);
        self.refresh_roots();
        Ok(member_id)
    }

    pub fn open_epoch(
        &mut self,
        request: BeaconEpochRequest,
    ) -> PrivateL2PqConfidentialQuantumRandomBeaconCommitteeRuntimeResult<String> {
        require(
            request.committee_member_ids.len() >= self.config.min_committee_size,
            "committee is below minimum size",
        )?;
        require(
            request.committee_member_ids.len() <= self.config.max_committee_size,
            "committee exceeds maximum size",
        )?;
        for member_id in &request.committee_member_ids {
            require(
                self.committee_members.contains_key(member_id),
                "epoch references an unknown committee member",
            )?;
        }
        let committee_root = merkle_root(
            "PRIVATE-L2-PQ-QRB-EPOCH-COMMITTEE",
            &request
                .committee_member_ids
                .iter()
                .map(|member_id| json!({ "member_id": member_id }))
                .collect::<Vec<_>>(),
        );
        let epoch_id = id_from_record(
            "PRIVATE-L2-PQ-QRB-EPOCH-ID",
            &json!({
                "epoch_index": request.epoch_index,
                "start_height": request.start_height,
                "committee_root": committee_root,
                "seed_commitment_root": request.seed_commitment_root,
                "nonce": request.nonce,
            }),
        );
        let committee_len = request.committee_member_ids.len() as u64;
        let min_reveals = ceil_bps(committee_len, self.config.threshold_bps).max(1);
        let record = BeaconEpochRecord {
            epoch_id: epoch_id.clone(),
            epoch_index: request.epoch_index,
            start_height: request.start_height,
            seal_deadline_height: request.start_height + self.config.epoch_length_blocks,
            reveal_deadline_height: request.start_height
                + self.config.epoch_length_blocks
                + self.config.reveal_window_blocks,
            committee_root,
            seed_commitment_root: request.seed_commitment_root,
            min_reveals,
            status: EpochStatus::Sealing,
            randomness_root: None,
            transcript_id: None,
            fairness_anchor_root: request.fairness_anchor_root,
        };
        self.epochs.insert(epoch_id.clone(), record);
        self.refresh_roots();
        Ok(epoch_id)
    }

    pub fn seal_entropy_share(
        &mut self,
        request: SealedEntropyShareRequest,
    ) -> PrivateL2PqConfidentialQuantumRandomBeaconCommitteeRuntimeResult<String> {
        let epoch = self
            .epochs
            .get(&request.epoch_id)
            .ok_or_else(|| "share references an unknown epoch".to_string())?;
        require(
            epoch.status.accepts_shares(),
            "epoch is not accepting shares",
        )?;
        require(
            self.committee_members.contains_key(&request.member_id),
            "share references an unknown committee member",
        )?;
        require(
            request.submitted_height <= epoch.seal_deadline_height,
            "share was submitted after the seal deadline",
        )?;
        require(
            request.entropy_bits >= 256,
            "sealed share entropy is too small",
        )?;

        let share_id = id_from_record(
            "PRIVATE-L2-PQ-QRB-SEALED-SHARE-ID",
            &json!({
                "epoch_id": request.epoch_id,
                "member_id": request.member_id,
                "sealed_entropy_commitment": request.sealed_entropy_commitment,
                "ciphertext_root": request.ciphertext_root,
                "nonce": request.nonce,
            }),
        );
        let record = SealedEntropyShareRecord {
            share_id: share_id.clone(),
            epoch_id: request.epoch_id,
            member_id: request.member_id,
            sealed_entropy_commitment: request.sealed_entropy_commitment,
            ciphertext_root: request.ciphertext_root,
            pq_proof_root: request.pq_proof_root,
            submitted_height: request.submitted_height,
            reveal_height: None,
            status: ShareStatus::Sealed,
            entropy_bits: request.entropy_bits,
            redaction_budget_id: request.redaction_budget_id,
        };
        self.sealed_shares.insert(share_id.clone(), record);
        self.refresh_roots();
        Ok(share_id)
    }

    pub fn reveal_share(
        &mut self,
        share_id: &str,
        reveal_height: u64,
    ) -> PrivateL2PqConfidentialQuantumRandomBeaconCommitteeRuntimeResult<()> {
        let epoch_id = self
            .sealed_shares
            .get(share_id)
            .map(|share| share.epoch_id.clone())
            .ok_or_else(|| "unknown share".to_string())?;
        let epoch = self
            .epochs
            .get(&epoch_id)
            .ok_or_else(|| "share references an unknown epoch".to_string())?;
        let share = self
            .sealed_shares
            .get_mut(share_id)
            .ok_or_else(|| "unknown share".to_string())?;
        if reveal_height > epoch.reveal_deadline_height {
            share.status = ShareStatus::Stale;
        } else {
            share.status = ShareStatus::Revealed;
            share.reveal_height = Some(reveal_height);
        }
        self.refresh_roots();
        Ok(())
    }

    pub fn finalize_epoch(
        &mut self,
        epoch_id: &str,
        finalized_height: u64,
    ) -> PrivateL2PqConfidentialQuantumRandomBeaconCommitteeRuntimeResult<String> {
        let epoch = self
            .epochs
            .get(epoch_id)
            .ok_or_else(|| "unknown epoch".to_string())?
            .clone();
        let included_shares = self
            .sealed_shares
            .values()
            .filter(|share| share.epoch_id == epoch_id && share.status == ShareStatus::Revealed)
            .map(|share| share.public_record())
            .collect::<Vec<_>>();
        require(
            included_shares.len() as u64 >= epoch.min_reveals,
            "not enough revealed shares to finalize the epoch",
        )?;
        let excluded_shares = self
            .sealed_shares
            .values()
            .filter(|share| share.epoch_id == epoch_id && share.status != ShareStatus::Revealed)
            .map(|share| share.public_record())
            .collect::<Vec<_>>();
        let included_share_root =
            merkle_root("PRIVATE-L2-PQ-QRB-INCLUDED-SHARES", &included_shares);
        let excluded_share_root =
            merkle_root("PRIVATE-L2-PQ-QRB-EXCLUDED-SHARES", &excluded_shares);
        let reveal_order_root = merkle_root(
            "PRIVATE-L2-PQ-QRB-REVEAL-ORDER",
            &included_shares
                .iter()
                .enumerate()
                .map(|(index, share)| json!({ "index": index, "share": share }))
                .collect::<Vec<_>>(),
        );
        let randomness_output_root = record_root(
            "PRIVATE-L2-PQ-QRB-RANDOMNESS-OUTPUT",
            &json!({
                "epoch_id": epoch_id,
                "included_share_root": included_share_root,
                "fairness_anchor_root": epoch.fairness_anchor_root,
                "seed_commitment_root": epoch.seed_commitment_root,
            }),
        );
        let deterministic_mix_root = record_root(
            "PRIVATE-L2-PQ-QRB-DETERMINISTIC-MIX",
            &json!({
                "epoch_id": epoch_id,
                "randomness_output_root": randomness_output_root,
                "included_share_root": included_share_root,
                "excluded_share_root": excluded_share_root,
            }),
        );
        let transcript_id = id_from_record(
            "PRIVATE-L2-PQ-QRB-TRANSCRIPT-ID",
            &json!({
                "epoch_id": epoch_id,
                "randomness_output_root": randomness_output_root,
                "finalized_height": finalized_height,
            }),
        );
        let transcript = RandomnessTranscriptRecord {
            transcript_id: transcript_id.clone(),
            epoch_id: epoch_id.to_string(),
            included_share_root,
            excluded_share_root,
            reveal_order_root,
            randomness_output_root: randomness_output_root.clone(),
            deterministic_mix_root,
            verifier_attestation_root: sample_root("verifier-attestation", finalized_height),
            finalized_height,
            included_shares: included_shares.len() as u64,
        };
        for share in self.sealed_shares.values_mut() {
            if share.epoch_id == epoch_id && share.status == ShareStatus::Revealed {
                share.status = ShareStatus::Included;
            }
        }
        if let Some(epoch) = self.epochs.get_mut(epoch_id) {
            epoch.status = EpochStatus::Finalized;
            epoch.randomness_root = Some(randomness_output_root);
            epoch.transcript_id = Some(transcript_id.clone());
        }
        self.randomness_transcripts
            .insert(transcript_id.clone(), transcript);
        self.refresh_roots();
        Ok(transcript_id)
    }

    pub fn record_bias_audit(
        &mut self,
        mut record: BiasAuditRecord,
    ) -> PrivateL2PqConfidentialQuantumRandomBeaconCommitteeRuntimeResult<()> {
        require(
            self.epochs.contains_key(&record.epoch_id),
            "audit references an unknown epoch",
        )?;
        require(
            self.randomness_transcripts
                .contains_key(&record.transcript_id),
            "audit references an unknown transcript",
        )?;
        record.max_bias_score_bps = self.config.max_bias_score_bps;
        record.passed = record.bias_score_bps <= self.config.max_bias_score_bps;
        if let Some(epoch) = self.epochs.get_mut(&record.epoch_id) {
            epoch.status = if record.passed {
                EpochStatus::Audited
            } else {
                EpochStatus::Quarantined
            };
        }
        self.bias_audits.insert(record.audit_id.clone(), record);
        self.refresh_roots();
        Ok(())
    }

    pub fn quarantine_stale_share(
        &mut self,
        record: StaleShareQuarantineRecord,
    ) -> PrivateL2PqConfidentialQuantumRandomBeaconCommitteeRuntimeResult<()> {
        require(
            self.sealed_shares.contains_key(&record.share_id),
            "quarantine references an unknown share",
        )?;
        if let Some(share) = self.sealed_shares.get_mut(&record.share_id) {
            share.status = ShareStatus::Quarantined;
        }
        if let Some(member) = self.committee_members.get_mut(&record.member_id) {
            member.quarantined_until_height = Some(record.quarantine_until_height);
        }
        self.stale_share_quarantines
            .insert(record.quarantine_id.clone(), record);
        self.refresh_roots();
        Ok(())
    }

    pub fn reserve_low_fee_rebate(
        &mut self,
        mut record: LowFeeBeaconRebateRecord,
    ) -> PrivateL2PqConfidentialQuantumRandomBeaconCommitteeRuntimeResult<()> {
        require(
            self.config.allow_low_fee_rebates,
            "low-fee rebates are disabled",
        )?;
        require(
            record.max_fee_micronero <= self.config.low_fee_limit_micronero,
            "rebate fee ceiling exceeds low-fee limit",
        )?;
        require(
            self.committee_members.contains_key(&record.member_id),
            "rebate references an unknown member",
        )?;
        record.status = RebateStatus::Reserved;
        self.low_fee_rebates
            .insert(record.rebate_id.clone(), record);
        self.refresh_roots();
        Ok(())
    }

    pub fn record_redaction_budget(
        &mut self,
        record: PrivacyRedactionBudgetRecord,
    ) -> PrivateL2PqConfidentialQuantumRandomBeaconCommitteeRuntimeResult<()> {
        require(
            record.spent_units <= record.budget_units,
            "redaction budget is overspent",
        )?;
        require(
            record.budget_units <= self.config.privacy_redaction_budget,
            "redaction budget exceeds configured maximum",
        )?;
        self.privacy_redaction_budgets
            .insert(record.budget_id.clone(), record);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_fixture(&mut self, record: FixtureRecord) {
        self.fixtures.insert(record.fixture_id.clone(), record);
        self.refresh_roots();
    }

    pub fn counters(&self) -> Counters {
        Counters {
            epochs: self.epochs.len() as u64,
            committee_members: self.committee_members.len() as u64,
            sealed_shares: self.sealed_shares.len() as u64,
            revealed_shares: self
                .sealed_shares
                .values()
                .filter(|share| {
                    matches!(share.status, ShareStatus::Revealed | ShareStatus::Included)
                })
                .count() as u64,
            transcripts: self.randomness_transcripts.len() as u64,
            bias_audits: self.bias_audits.len() as u64,
            stale_share_quarantines: self.stale_share_quarantines.len() as u64,
            low_fee_rebates: self.low_fee_rebates.len() as u64,
            privacy_redaction_budgets: self.privacy_redaction_budgets.len() as u64,
            fixture_records: self.fixtures.len() as u64,
            total_entropy_bits: self
                .sealed_shares
                .values()
                .map(|share| share.entropy_bits as u128)
                .sum(),
            total_rebate_micronero: self
                .low_fee_rebates
                .values()
                .map(|rebate| rebate.max_fee_micronero as u128)
                .sum(),
        }
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: record_root(
                "PRIVATE-L2-PQ-QRB-CONFIG-ROOT",
                &self.config.public_record(),
            ),
            epoch_root: map_root("PRIVATE-L2-PQ-QRB-EPOCH-ROOT", &self.epochs, |record| {
                record.public_record()
            }),
            committee_member_root: map_root(
                "PRIVATE-L2-PQ-QRB-COMMITTEE-MEMBER-ROOT",
                &self.committee_members,
                |record| record.public_record(),
            ),
            sealed_share_root: map_root(
                "PRIVATE-L2-PQ-QRB-SEALED-SHARE-ROOT",
                &self.sealed_shares,
                |record| record.public_record(),
            ),
            randomness_transcript_root: map_root(
                "PRIVATE-L2-PQ-QRB-TRANSCRIPT-ROOT",
                &self.randomness_transcripts,
                |record| record.public_record(),
            ),
            bias_audit_root: map_root(
                "PRIVATE-L2-PQ-QRB-BIAS-AUDIT-ROOT",
                &self.bias_audits,
                |record| record.public_record(),
            ),
            stale_share_quarantine_root: map_root(
                "PRIVATE-L2-PQ-QRB-STALE-QUARANTINE-ROOT",
                &self.stale_share_quarantines,
                |record| record.public_record(),
            ),
            low_fee_rebate_root: map_root(
                "PRIVATE-L2-PQ-QRB-LOW-FEE-REBATE-ROOT",
                &self.low_fee_rebates,
                |record| record.public_record(),
            ),
            privacy_redaction_budget_root: map_root(
                "PRIVATE-L2-PQ-QRB-REDACTION-BUDGET-ROOT",
                &self.privacy_redaction_budgets,
                |record| record.public_record(),
            ),
            fixture_root: map_root("PRIVATE-L2-PQ-QRB-FIXTURE-ROOT", &self.fixtures, |record| {
                record.public_record()
            }),
            public_record_root: map_value_root(
                "PRIVATE-L2-PQ-QRB-PUBLIC-RECORD-ROOT",
                &self.public_records,
            ),
        }
    }

    pub fn refresh_roots(&mut self) {
        self.counters = self.counters();
        self.roots = self.roots();
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": self.roots().public_record(),
            "operator_safe_summary": self.operator_safe_summary_without_state_root().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = Value::String(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn operator_safe_summary(&self) -> OperatorSafeSummary {
        let mut summary = self.operator_safe_summary_without_state_root();
        summary.state_root = self.state_root();
        summary
    }

    fn operator_safe_summary_without_state_root(&self) -> OperatorSafeSummary {
        let counters = self.counters();
        OperatorSafeSummary {
            state_root: String::new(),
            active_epochs: self
                .epochs
                .values()
                .filter(|epoch| {
                    matches!(epoch.status, EpochStatus::Sealing | EpochStatus::Revealing)
                })
                .count() as u64,
            active_members: self
                .committee_members
                .values()
                .filter(|member| member.quarantined_until_height.is_none())
                .count() as u64,
            sealed_shares: counters.sealed_shares,
            finalized_transcripts: counters.transcripts,
            quarantined_shares: counters.stale_share_quarantines,
            total_rebate_micronero: counters.total_rebate_micronero,
            pq_security_floor_bits: self.config.min_pq_security_bits,
            public_record_root: self.roots.public_record_root.clone(),
        }
    }
}

pub fn devnet() -> State {
    let mut state = State::default();

    let budget = PrivacyRedactionBudgetRecord {
        budget_id: sample_id("redaction-budget", 1),
        owner_commitment: sample_commitment("budget-owner", 1),
        epoch_id: None,
        budget_units: 64,
        spent_units: 9,
        redaction_policy_root: sample_root("redaction-policy", 1),
        nullifier_root: sample_root("redaction-nullifier", 1),
    };
    let budget_id = budget.budget_id.clone();
    state
        .record_redaction_budget(budget)
        .expect("devnet redaction budget");

    let member_a = state
        .register_committee_member(CommitteeMemberRequest {
            operator_commitment: sample_commitment("operator", 1),
            pq_key_commitment: sample_commitment("pq-key", 1),
            algorithm: PqAlgorithm::MlKem1024MlDsa87,
            roles: BTreeSet::from([
                CommitteeRole::EntropyDealer,
                CommitteeRole::ShareSealer,
                CommitteeRole::RevealVerifier,
            ]),
            stake_commitment: sample_commitment("stake", 1),
            privacy_group_root: sample_root("privacy-group", 1),
            availability_score_bps: 9_850,
            fairness_weight: 100,
            active_from_epoch: 0,
            nonce: "devnet-member-1".to_string(),
        })
        .expect("devnet member a");
    let member_b = state
        .register_committee_member(CommitteeMemberRequest {
            operator_commitment: sample_commitment("operator", 2),
            pq_key_commitment: sample_commitment("pq-key", 2),
            algorithm: PqAlgorithm::SlhDsaShake256f,
            roles: BTreeSet::from([CommitteeRole::EntropyDealer, CommitteeRole::BiasAuditor]),
            stake_commitment: sample_commitment("stake", 2),
            privacy_group_root: sample_root("privacy-group", 2),
            availability_score_bps: 9_760,
            fairness_weight: 98,
            active_from_epoch: 0,
            nonce: "devnet-member-2".to_string(),
        })
        .expect("devnet member b");
    let member_c = state
        .register_committee_member(CommitteeMemberRequest {
            operator_commitment: sample_commitment("operator", 3),
            pq_key_commitment: sample_commitment("pq-key", 3),
            algorithm: PqAlgorithm::MlKem1024MlDsa87,
            roles: BTreeSet::from([CommitteeRole::ShareSealer, CommitteeRole::RebateSponsor]),
            stake_commitment: sample_commitment("stake", 3),
            privacy_group_root: sample_root("privacy-group", 3),
            availability_score_bps: 9_680,
            fairness_weight: 96,
            active_from_epoch: 0,
            nonce: "devnet-member-3".to_string(),
        })
        .expect("devnet member c");
    let member_d = state
        .register_committee_member(CommitteeMemberRequest {
            operator_commitment: sample_commitment("operator", 4),
            pq_key_commitment: sample_commitment("pq-key", 4),
            algorithm: PqAlgorithm::SlhDsaShake256f,
            roles: BTreeSet::from([
                CommitteeRole::RevealVerifier,
                CommitteeRole::EmergencyObserver,
            ]),
            stake_commitment: sample_commitment("stake", 4),
            privacy_group_root: sample_root("privacy-group", 4),
            availability_score_bps: 9_550,
            fairness_weight: 94,
            active_from_epoch: 0,
            nonce: "devnet-member-4".to_string(),
        })
        .expect("devnet member d");
    let member_e = state
        .register_committee_member(CommitteeMemberRequest {
            operator_commitment: sample_commitment("operator", 5),
            pq_key_commitment: sample_commitment("pq-key", 5),
            algorithm: PqAlgorithm::MlKem1024MlDsa87,
            roles: BTreeSet::from([CommitteeRole::EntropyDealer, CommitteeRole::BiasAuditor]),
            stake_commitment: sample_commitment("stake", 5),
            privacy_group_root: sample_root("privacy-group", 5),
            availability_score_bps: 9_430,
            fairness_weight: 92,
            active_from_epoch: 0,
            nonce: "devnet-member-5".to_string(),
        })
        .expect("devnet member e");

    let epoch_id = state
        .open_epoch(BeaconEpochRequest {
            epoch_index: 7,
            start_height: DEVNET_HEIGHT,
            committee_member_ids: vec![
                member_a.clone(),
                member_b.clone(),
                member_c.clone(),
                member_d.clone(),
                member_e.clone(),
            ],
            seed_commitment_root: sample_root("epoch-seed", 7),
            fairness_anchor_root: sample_root("fairness-anchor", 7),
            nonce: "devnet-epoch-7".to_string(),
        })
        .expect("devnet epoch");

    let share_a = state
        .seal_entropy_share(SealedEntropyShareRequest {
            epoch_id: epoch_id.clone(),
            member_id: member_a.clone(),
            sealed_entropy_commitment: sample_commitment("sealed-entropy", 1),
            ciphertext_root: sample_root("ciphertext", 1),
            pq_proof_root: sample_root("pq-proof", 1),
            submitted_height: DEVNET_HEIGHT + 3,
            entropy_bits: 384,
            redaction_budget_id: Some(budget_id.clone()),
            nonce: "devnet-share-1".to_string(),
        })
        .expect("devnet share a");
    let share_b = state
        .seal_entropy_share(SealedEntropyShareRequest {
            epoch_id: epoch_id.clone(),
            member_id: member_b.clone(),
            sealed_entropy_commitment: sample_commitment("sealed-entropy", 2),
            ciphertext_root: sample_root("ciphertext", 2),
            pq_proof_root: sample_root("pq-proof", 2),
            submitted_height: DEVNET_HEIGHT + 4,
            entropy_bits: 384,
            redaction_budget_id: Some(budget_id.clone()),
            nonce: "devnet-share-2".to_string(),
        })
        .expect("devnet share b");
    let share_c = state
        .seal_entropy_share(SealedEntropyShareRequest {
            epoch_id: epoch_id.clone(),
            member_id: member_c.clone(),
            sealed_entropy_commitment: sample_commitment("sealed-entropy", 3),
            ciphertext_root: sample_root("ciphertext", 3),
            pq_proof_root: sample_root("pq-proof", 3),
            submitted_height: DEVNET_HEIGHT + 5,
            entropy_bits: 384,
            redaction_budget_id: Some(budget_id),
            nonce: "devnet-share-3".to_string(),
        })
        .expect("devnet share c");
    let share_d = state
        .seal_entropy_share(SealedEntropyShareRequest {
            epoch_id: epoch_id.clone(),
            member_id: member_d.clone(),
            sealed_entropy_commitment: sample_commitment("sealed-entropy", 4),
            ciphertext_root: sample_root("ciphertext", 4),
            pq_proof_root: sample_root("pq-proof", 4),
            submitted_height: DEVNET_HEIGHT + 6,
            entropy_bits: 384,
            redaction_budget_id: None,
            nonce: "devnet-share-4".to_string(),
        })
        .expect("devnet share d");

    state
        .reveal_share(&share_a, DEVNET_HEIGHT + DEFAULT_EPOCH_LENGTH_BLOCKS + 1)
        .expect("devnet reveal a");
    state
        .reveal_share(&share_b, DEVNET_HEIGHT + DEFAULT_EPOCH_LENGTH_BLOCKS + 2)
        .expect("devnet reveal b");
    state
        .reveal_share(&share_c, DEVNET_HEIGHT + DEFAULT_EPOCH_LENGTH_BLOCKS + 3)
        .expect("devnet reveal c");
    state
        .reveal_share(&share_d, DEVNET_HEIGHT + DEFAULT_EPOCH_LENGTH_BLOCKS + 30)
        .expect("devnet stale reveal");

    let transcript_id = state
        .finalize_epoch(&epoch_id, DEVNET_HEIGHT + DEFAULT_EPOCH_LENGTH_BLOCKS + 4)
        .expect("devnet finalize");
    state
        .record_bias_audit(BiasAuditRecord {
            audit_id: sample_id("bias-audit", 1),
            epoch_id: epoch_id.clone(),
            transcript_id,
            auditor_commitment: sample_commitment("auditor", 1),
            sample_window_root: sample_root("audit-window", 1),
            bias_score_bps: 41,
            max_bias_score_bps: 0,
            passed: false,
            public_summary_root: sample_root("audit-summary", 1),
        })
        .expect("devnet bias audit");
    state
        .quarantine_stale_share(StaleShareQuarantineRecord {
            quarantine_id: sample_id("stale-quarantine", 1),
            share_id: share_d,
            member_id: member_d,
            epoch_id: epoch_id.clone(),
            reason_code: "reveal-after-window".to_string(),
            evidence_root: sample_root("stale-evidence", 1),
            quarantine_until_height: DEVNET_HEIGHT + DEFAULT_QUARANTINE_BLOCKS,
            rebate_revoked: true,
        })
        .expect("devnet quarantine");
    state
        .reserve_low_fee_rebate(LowFeeBeaconRebateRecord {
            rebate_id: sample_id("low-fee-rebate", 1),
            epoch_id,
            member_id: member_e,
            fee_commitment: sample_commitment("fee", 1),
            rebate_commitment: sample_commitment("rebate", 1),
            max_fee_micronero: DEFAULT_LOW_FEE_LIMIT_MICRONERO,
            expires_at_height: DEVNET_HEIGHT + DEFAULT_REBATE_TTL_BLOCKS,
            status: RebateStatus::Reserved,
        })
        .expect("devnet rebate");
    state.insert_fixture(FixtureRecord {
        fixture_id: sample_id("fixture", 1),
        label: "devnet confidential quantum random beacon committee".to_string(),
        fixture_root: sample_root("fixture-root", 1),
        deterministic_seed_root: sample_root("fixture-seed", 1),
        notes_root: sample_root("fixture-notes", 1),
    });
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn require(
    condition: bool,
    message: &str,
) -> PrivateL2PqConfidentialQuantumRandomBeaconCommitteeRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_algorithm(
    config: &Config,
    algorithm: PqAlgorithm,
) -> PrivateL2PqConfidentialQuantumRandomBeaconCommitteeRuntimeResult<()> {
    require(
        config.allowed_algorithms.contains(&algorithm),
        "PQ algorithm is not enabled",
    )
}

fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-QRB-STATE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn id_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        16,
    )
}

fn sample_id(label: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-QRB-SAMPLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(sequence),
        ],
        16,
    )
}

fn sample_root(label: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-QRB-SAMPLE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(sequence),
        ],
        32,
    )
}

fn sample_commitment(label: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-QRB-SAMPLE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(sequence),
        ],
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": public_record(value) }))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn map_value_root(domain: &str, map: &BTreeMap<String, Value>) -> String {
    let records = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn ceil_bps(value: u64, bps: u64) -> u64 {
    (value * bps + MAX_BPS - 1) / MAX_BPS
}
